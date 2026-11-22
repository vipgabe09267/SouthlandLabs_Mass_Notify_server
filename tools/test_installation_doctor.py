#!/usr/bin/python3
"""Read-only diagnostics, bundle authenticity and disposable VM boundaries."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import socket
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or os.environ.get(
    'SLS_TEST_PARENT_NET_NS'
) in (None, '', os.readlink('/proc/self/ns/net')):
    raise SystemExit('Use the private fixture runner; doctor network isolation verification failed.')

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
DOCTOR=load('doctor_fixture',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_doctor.py')
BUNDLE=load('bundle_fixture',ROOT/'tools/prepare_offline_install.py')
VM=load('vm_fixture',ROOT/'tools/qualify_installer_vm.py')


class Doctor(unittest.TestCase):
    def assert_process_retired(self, pid):
        state = Path('/proc') / str(pid) / 'stat'
        for _ in range(30):
            try:
                process_state = state.read_text().rsplit(')', 1)[1].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                return
            if process_state == 'Z':
                return
            time.sleep(.01)
        self.fail(f'Diagnostic child {pid} survived its deadline')

    def test_service_writable_diagnostic_dependency_is_refused_before_parsing(self):
        with tempfile.TemporaryDirectory(prefix='sls-doctor-source-',dir='/run') as temporary:
            folder=Path(temporary)
            runtime=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
            for name in ('sls_install_doctor.py','sls_php_security.py','sls_web_readiness.py','php-security-policy.json'):
                shutil.copyfile(runtime/name,folder/name)
                (folder/name).chmod(0o600)
            helper=folder/'sls_php_security.py'
            helper.write_text('invalid Python input that must not be parsed\n');helper.chmod(0o666)
            result=subprocess.run(['/usr/bin/python3','-I','-c',
                'import runpy,sys; runpy.run_path(sys.argv[1],run_name="diagnostic_fixture")',str(folder/'sls_install_doctor.py')],
                capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Diagnostic helper source is unsafe',result.stderr)
            self.assertNotIn('SyntaxError',result.stderr)

    def test_security_policy_has_matching_php_python_and_installer_floors(self):
        policy = load('php_security_fixture', ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_php_security.py')
        versions = ['8.2.34','8.2.35','8.2.35-1~deb12u1','8.3.36','8.4.26','8.5.12','8.2.35RC1','8.2.35-dev','8.6.0','invalid']
        php = ROOT/'slsmassnotifyserver/api/sls-mass-notify/runtime-security.php'
        result = subprocess.run(['php','-r','require $argv[1]; echo json_encode(array_map(static fn($v)=>\\SLS\\MassNotify\\PhpSecurityPolicy::evaluate($v),json_decode($argv[2],true)));',str(php),json.dumps(versions)],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout), [policy.evaluate(version) for version in versions])
        catalog = json.loads((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/php-security-policy.json').read_text())
        source = (ROOT/'tools/install_release.sh').read_text()
        literal = re.search(r'\$securityFloors=(\[[^\n]+\]);',source).group(1)
        self.assertEqual(dict(re.findall(r'"([0-9.]+)"=>"([0-9.]+)"',literal)),catalog['branches'])
        self.assertFalse(policy.evaluate('8.2.34')['ok'])
        self.assertFalse(policy.evaluate('8.2.35RC1')['ok'])
        self.assertTrue(policy.evaluate('8.2.35-1~deb12u1')['ok'])

    def test_stale_served_php_cannot_pass_a_patched_cli_policy(self):
        payload=self.php_payload();payload['php_version']='8.2.34';payload['ok']=False;payload['missing']=['php_security_floor']
        value=DOCTOR.served_php_probe(self.php_server(payload,503))
        self.assertTrue(value['available']);self.assertFalse(value['ok'])

    def test_diagnostic_and_transaction_stages_share_the_installer_contract(self):
        transaction=load('transaction_stages',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py')
        self.assertEqual(DOCTOR.STAGES,transaction.STAGES)
        emitted=set(re.findall(r"""^\s*set_install_stage ['"]([^'"$]+)['"]""", (ROOT/'tools/install_release.sh').read_text(), re.M))
        self.assertLessEqual(emitted,DOCTOR.STAGES)
    def php_payload(self):
        return {'probe':'sls_served_php_v1','ok':True,'missing':[],'php_version':'8.2.35','php_sapi':'fpm-fcgi',
                'runtime_account_ok':True,'extensions':dict.fromkeys(DOCTOR.PHP_EXTENSIONS,True),
                'functions':dict.fromkeys(DOCTOR.PHP_FUNCTIONS,True),'api_key':'must-not-appear','uid':999}
    def php_server(self,payload,status=200,slow=False):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    if slow:
                        for unused in range(50):self.connection.sendall(b'x');time.sleep(.03)
                        return
                    self.send_response(status)
                    if status==302:self.send_header('Location','https://provider.example.test/secret')
                    self.end_headers();self.wfile.write(payload if isinstance(payload,bytes) else json.dumps(payload).encode())
                except OSError:pass
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return [('http','127.0.0.1',server.server_port,'pbx.example.test')]
    def test_freepbx_http_200_loader_error_is_not_readiness(self):
        body=b'#!/usr/bin/env php\nScript error: the <b>ionCube</b> Loader for PHP needs to be installed. private-error-marker'
        value=DOCTOR.freepbx_gui_probe(self.php_server(body))
        self.assertFalse(value['ok']);self.assertTrue(value['available'])
        self.assertEqual(value['failure_code'],'freepbx_vendor_loader_unavailable')
        self.assertNotIn('private-error-marker',json.dumps(value))
    def test_freepbx_gui_probe_checks_body_bounds_status_and_keeps_redirects_local(self):
        valid=b'<!doctype html><html><body><form id="loginform"></form></body></html>'
        self.assertTrue(DOCTOR.freepbx_gui_probe(self.php_server(valid))['ok'])
        for body,status in [(b'',200),(b'not an HTML page',200),(b'<html>error</html>',500),(valid+b'x'*1048576,200)]:
            with self.subTest(status=status,bytes=len(body)):
                self.assertFalse(DOCTOR.freepbx_gui_probe(self.php_server(body,status))['ok'])
        for status in (302,401,403):
            value=DOCTOR.freepbx_gui_probe(self.php_server(valid,status))
            self.assertTrue(value['available']);self.assertTrue(value['access_limited']);self.assertFalse(value['authenticated'])
        with patch.object(DOCTOR.http.client,'HTTPConnection',side_effect=AssertionError('External connection attempted')):
            self.assertFalse(DOCTOR.freepbx_gui_probe([('http','192.0.2.1',80,'pbx.example.test')])['available'])
    def test_unrelated_html_never_masks_a_later_native_loader_failure(self):
        unrelated=self.php_server(b'<!doctype html><html><body>unrelated hosted site</body></html>')
        loader=self.php_server(b'<html>Script error: the ionCube Loader for PHP needs to be installed.</html>')
        value=DOCTOR.freepbx_gui_probe(unrelated+loader)
        self.assertFalse(value['ok'])
        self.assertEqual(value['failure_code'],'freepbx_vendor_loader_unavailable')
        valid=self.php_server(b'<!doctype html><html><form id="loginform"></form></html>')
        self.assertTrue(DOCTOR.freepbx_gui_probe(unrelated+valid)['ok'])
    def test_freepbx_gui_probe_has_an_absolute_slow_header_deadline(self):
        started=time.monotonic();value=DOCTOR.freepbx_gui_probe(self.php_server({},slow=True),.15)
        self.assertFalse(value['ok']);self.assertLess(time.monotonic()-started,.6)
    def test_diagnostics_never_start_services_install_packages_or_load_php(self):
        commands=[]
        def command(args,timeout=5):
            commands.append(args)
            if args[0].endswith('systemctl'): return 0,'active\n'
            if args[0].endswith('apache2ctl'): return 0,'Syntax OK\n'
            return 1,'{}'
        with patch.object(DOCTOR,'command',side_effect=command),patch.object(DOCTOR,'served_php_local',return_value={'ok':False,'available':False}): value=DOCTOR.report()
        self.assertTrue(value['read_only'])
        self.assertNotIn('mass-notifications.config',json.dumps(value))
        for args in commands:
            self.assertNotIn('start',args);self.assertNotIn('restart',args);self.assertNotIn('reload',args)
            self.assertNotIn('php',Path(args[0]).name);self.assertNotIn('apt-get',args);self.assertNotIn('fwconsole',args)
        self.assertIn('physical endpoints',value['not_exercised'])
    def test_unsafe_runtime_helper_is_not_executed(self):
        with patch.object(DOCTOR,'protected',return_value=False),patch.object(DOCTOR,'command',return_value=(0,'active')) as command,patch.object(DOCTOR,'served_php_local',return_value={'ok':False,'available':False}):
            value=DOCTOR.report()
        self.assertFalse(any('sls_resource_capacity.py' in argument for call in command.call_args_list for argument in call.args[0]))
        self.assertIn('resource_helper_unsafe_or_missing',json.dumps(value))
    def test_invalid_capacity_rejected_without_probes(self):
        result=subprocess.run(['python3','-I',str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_doctor.py'),'--desktop-limit','1001'],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,2)
    def test_resource_probe_uses_active_or_explicit_deployment_profile(self):
        payload={'schema':1,'deployment_profile':'lite','requested_limit':25,
                 'requested_phone_limit':25,'eligible_limit':25,'eligible_phone_limit':25,
                 'requirements':{},'resource_checks':{}}
        with patch.object(DOCTOR,'protected',return_value=True), \
             patch.object(DOCTOR,'command',return_value=(0,json.dumps(payload))) as command:
            result=DOCTOR.resource_probe(25,25,'lite')
        self.assertTrue(result['ok']);self.assertEqual(result['allocation']['deployment_profile'],'lite')
        self.assertEqual(command.call_args.args[0][-2:],['--profile','lite'])
    def test_root_resource_probe_uses_the_pbx_account_for_storage_traversal(self):
        payload={'schema':1,'deployment_profile':'lite','resource_checks':{}}
        with patch.object(DOCTOR,'protected',return_value=True), \
             patch.object(DOCTOR.os,'geteuid',return_value=0), \
             patch.object(DOCTOR,'command',return_value=(0,json.dumps(payload))) as command:
            self.assertTrue(DOCTOR.resource_probe(25,25,'lite')['ok'])
        self.assertEqual(command.call_args.args[0][:6],
                         ['/usr/sbin/runuser','-u','asterisk','--','/usr/bin/python3','-I'])

    def test_operational_resource_health_does_not_require_another_installation_workspace(self):
        # Actual committed ISO17 observation: native CPU/RAM passed; routine
        # runtime headroom fits, while the hypothetical install forecast does
        # not fit /var, /usr/local or /tmp. No volume or reserve is changed.
        def probe(arguments, timeout):
            mode = arguments[arguments.index('--mode') + 1]
            if mode == 'runtime':
                rows = [('/var', 1237188608, 162529280),
                        ('/tmp', 394905600, 231266304)]
            else:
                rows = [('/var', 1237204992, 2129610752),
                        ('/usr/local', 181364736, 291119104),
                        ('/tmp', 394336256, 1135976448)]
            fits = all(actual >= required for unused, actual, required in rows)
            value = {'schema': 1, 'deployment_profile': 'standard',
                     'requirements': {'storage': {'mode': mode}},
                     'resource_checks': {'cpu': {'ok': True}, 'memory': {'ok': True},
                         'storage': {'ok': fits, 'filesystems': [
                             {'paths': [path], 'actual': actual, 'required': required}
                             for path, actual, required in rows]}}}
            return (0 if fits else 2), json.dumps(value)
        for budget in ('quick', 'deep'):
            with self.subTest(budget=budget), \
                 patch.object(DOCTOR, 'protected', return_value=True), \
                 patch.object(DOCTOR.os, 'geteuid', return_value=0), \
                 patch.object(DOCTOR, 'command', side_effect=probe):
                value = DOCTOR.resource_probe(25, 25, 'standard', budget=budget)
            self.assertTrue(value['ok'], 'Installed health incorrectly requires future installation workspace')
            self.assertEqual(value['allocation']['requirements']['storage']['mode'], 'runtime')

    def test_operational_capacity_still_fails_real_limits_unreadable_probes_and_timeouts(self):
        for failed in ('cpu', 'memory', 'storage', 'temporary'):
            payload = {'schema': 1, 'deployment_profile': 'standard',
                       'requirements': {'storage': {'mode': 'runtime'}},
                       'resource_checks': {name: {'ok': name != failed}
                           for name in ('cpu', 'memory', 'storage', 'temporary')}}
            with self.subTest(failed=failed), \
                 patch.object(DOCTOR, 'protected', return_value=True), \
                 patch.object(DOCTOR, 'command', return_value=(2, json.dumps(payload))):
                self.assertFalse(DOCTOR.resource_probe(25, 25)['ok'])
        for status, body, expected in ((124, '', 'resource_probe_timeout'),
                                       (2, 'not JSON', 'resource_probe_invalid')):
            with self.subTest(status=status), \
                 patch.object(DOCTOR, 'protected', return_value=True), \
                 patch.object(DOCTOR, 'command', return_value=(status, body)):
                self.assertEqual(DOCTOR.resource_probe(25, 25)['failure_code'], expected)
        with patch.object(DOCTOR, 'protected', return_value=False), \
             patch.object(DOCTOR, 'command', side_effect=AssertionError('Unsafe helper executed')):
            self.assertEqual(DOCTOR.resource_probe(25, 25)['failure_code'], 'resource_helper_unsafe_or_missing')

    def test_root_cli_deep_budget_is_fixed_and_quick_report_budget_stays_five_seconds(self):
        self.assertTrue(callable(getattr(DOCTOR,'probe_timeouts',None)),
                        'Root CLI diagnostics need a separate fixed budget from the web report')
        with patch.object(DOCTOR.os,'geteuid',return_value=0), \
             patch.dict(os.environ,{'SLS_DOCTOR_TIMEOUT':'999999','SLS_DIAGNOSTIC_BUDGET':'deep'}):
            self.assertEqual(DOCTOR.probe_timeouts('quick'),(5,5))
            self.assertEqual(DOCTOR.probe_timeouts('deep'),(15,18))
            for invalid in ('other','DEEP','deep\n',None,True,99):
                with self.subTest(invalid=invalid),self.assertRaises(ValueError):DOCTOR.probe_timeouts(invalid)
        with patch.object(DOCTOR.os,'geteuid',return_value=1000):
            self.assertEqual(DOCTOR.probe_timeouts('quick'),(5,5))
            with self.assertRaises(ValueError):DOCTOR.probe_timeouts('deep')

    def test_cli_main_selects_deep_only_as_root_without_turning_failure_into_success(self):
        for uid,budget in ((0,'deep'),(1000,'quick')):
            with self.subTest(uid=uid),patch.object(DOCTOR.os,'geteuid',return_value=uid), \
                 patch.object(DOCTOR.sys,'argv',['sls_install_doctor.py','--json']), \
                 patch.object(DOCTOR,'report',return_value={'ok':False}) as report, \
                 patch('builtins.print'):
                self.assertEqual(DOCTOR.main(),1)
                report.assert_called_once_with(25,25,None,budget=budget)

    def test_report_api_defaults_to_quick_and_nonroot_cannot_start_deep_probes(self):
        for arguments,budget in (({},'quick'),({'budget':'deep'},'deep')):
            with self.subTest(budget=budget),patch.object(DOCTOR.os,'geteuid',return_value=0), \
                 patch.object(DOCTOR,'command',return_value=(0,'active')), \
                 patch.object(DOCTOR,'served_php_local',return_value={'ok':False}), \
                 patch.object(DOCTOR,'freepbx_gui_local',return_value={'ok':False}), \
                 patch.object(DOCTOR,'collector_probe',return_value={'ok':False}) as collector, \
                 patch.object(DOCTOR,'release_probe',return_value={'ok':False}) as release, \
                 patch.object(DOCTOR,'resource_probe',return_value={'ok':False}) as resource:
                self.assertFalse(DOCTOR.report(**arguments)['ok'])
                release.assert_called_once_with(budget=budget)
                resource.assert_called_once_with(25,25,None,budget=budget)
                collector.assert_called_once_with(budget=budget)
        with patch.object(DOCTOR.os,'geteuid',return_value=1000), \
             patch.object(DOCTOR,'command',side_effect=AssertionError('No unauthorized deep query')):
            with self.assertRaises(ValueError):DOCTOR.report(budget='deep')

    def test_deep_probes_keep_native_identity_schemas_and_failures_with_larger_fixed_bounds(self):
        resource={'schema':1,'deployment_profile':'lite','resource_checks':{}}
        trust={'ok':True,'publisher_authenticated':True,'installed_inventory_matches':True,
               'stock_inventories':{'framework':True,'dashboard':True},'version':'0.2.0-beta',
               'package':'slsmassnotifyserver-0.2.0-beta.tgz','package_sha256':'a'*64,
               'installer_sha256':'b'*64,'inventory_sha256':'c'*64}
        with patch.object(DOCTOR.os,'geteuid',return_value=0),patch.object(DOCTOR,'protected',return_value=True):
            for budget,trust_timeout,resource_timeout in [('quick',5,5),('deep',15,18)]:
                with self.subTest(budget=budget),patch.object(DOCTOR,'command',return_value=(0,json.dumps(resource))) as command:
                    self.assertTrue(DOCTOR.resource_probe(25,25,'lite',budget=budget)['ok'])
                    self.assertEqual(command.call_args.args[1],resource_timeout)
                    self.assertEqual(command.call_args.args[0][:4],['/usr/sbin/runuser','-u','asterisk','--'])
                with patch.object(DOCTOR,'command',return_value=(0,json.dumps(trust))) as command:
                    self.assertTrue(DOCTOR.release_probe(budget=budget)['ok'])
                    self.assertEqual(command.call_args.args[1],trust_timeout)
                with patch.object(DOCTOR,'command',return_value=(124,'')):
                    self.assertEqual(DOCTOR.resource_probe(25,25,budget=budget)['failure_code'],'resource_probe_timeout')
                    self.assertEqual(DOCTOR.release_probe(budget=budget)['failure_code'],'release_trust_probe_timeout')
                with patch.object(DOCTOR,'command',return_value=(2,json.dumps(resource))):
                    self.assertFalse(DOCTOR.resource_probe(25,25,budget=budget)['ok'])
                with patch.object(DOCTOR,'command',return_value=(0,'{"schema":1}')):
                    self.assertEqual(DOCTOR.resource_probe(25,25,budget=budget)['failure_code'],'resource_probe_invalid')

    def test_timed_out_resource_helper_is_retired_and_never_reported_healthy_in_deep_mode(self):
        account=pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(dir='/run') as temporary:
            root=Path(temporary);root.chmod(0o755);pidfile=root/'pid'
            pidfile.touch();pidfile.chmod(0o600);os.chown(pidfile,account.pw_uid,account.pw_gid)
            helper=root/'sls_resource_capacity.py'
            helper.write_text('import os,time\nopen('+repr(str(pidfile))+',"w").write(str(os.getpid()))\ntime.sleep(20)\n')
            helper.chmod(0o755)
            with patch.object(DOCTOR,'RUNTIME',root),patch.object(DOCTOR,'probe_timeouts',return_value=(.2,.2)):
                value=DOCTOR.resource_probe(25,25,budget='deep')
            self.assertFalse(value['ok']);self.assertEqual(value['failure_code'],'resource_probe_timeout')
            self.assert_process_retired(int(pidfile.read_text()))

    def test_finite_resource_work_beyond_quick_deadline_can_complete_with_root_cli_budget(self):
        payload={'schema':1,'deployment_profile':'lite','resource_checks':{},'requested_limit':25}
        with tempfile.TemporaryDirectory(dir='/run') as temporary:
            root=Path(temporary);root.chmod(0o755);helper=root/'sls_resource_capacity.py'
            helper.write_text('import json,time\ntime.sleep(5.15)\nprint('+repr(json.dumps(payload))+')\n')
            helper.chmod(0o755)
            with patch.object(DOCTOR,'RUNTIME',root):
                # The same finite child exceeds the original shared five-second
                # ceiling. Its timeout is still a failure and must stop the child.
                quick=DOCTOR.resource_probe(25,25,'lite')
                self.assertFalse(quick['ok']);self.assertEqual(quick['failure_code'],'resource_probe_timeout')
                deep=DOCTOR.resource_probe(25,25,'lite',budget='deep')
                self.assertTrue(deep['ok']);self.assertEqual(deep['allocation']['deployment_profile'],'lite')
    def test_unprivileged_resource_probe_keeps_its_existing_account(self):
        payload={'schema':1,'deployment_profile':'lite','resource_checks':{}}
        with patch.object(DOCTOR,'protected',return_value=True), \
             patch.object(DOCTOR.os,'geteuid',return_value=1000), \
             patch.object(DOCTOR,'command',return_value=(0,json.dumps(payload))) as command:
            self.assertTrue(DOCTOR.resource_probe(25,25,'lite')['ok'])
        self.assertEqual(command.call_args.args[0][:2],['/usr/bin/python3','-I'])
    def test_served_runtime_uses_local_wire_evidence_and_redacts_extra_fields(self):
        value=DOCTOR.served_php_probe(self.php_server(self.php_payload()))
        self.assertTrue(value['ok']);self.assertEqual(value['php_version'],'8.2.35');self.assertEqual(value['php_sapi'],'fpm-fcgi')
        self.assertNotIn('must-not-appear',json.dumps(value));self.assertNotIn('uid',value)
        payload=self.php_payload();payload['ok']=False;payload['runtime_account_ok']=False;payload['functions']['exec']=False
        value=DOCTOR.served_php_probe(self.php_server(payload,503));self.assertTrue(value['available']);self.assertFalse(value['ok'])
        self.assertFalse(value['functions']['exec']);self.assertFalse(value['runtime_account_ok'])
    def test_php_redirects_external_targets_and_invalid_payloads_are_not_accepted(self):
        self.assertFalse(DOCTOR.served_php_probe(self.php_server(self.php_payload(),302))['available'])
        with patch.object(DOCTOR.http.client,'HTTPConnection',side_effect=AssertionError('External connection attempted')):
            self.assertFalse(DOCTOR.served_php_probe([('http','192.0.2.1',80,'pbx.example.test')])['available'])
        payload=self.php_payload();payload['functions']['exec']='yes'
        self.assertFalse(DOCTOR.served_php_probe(self.php_server(payload))['available'])
        payload=self.php_payload();payload['ok']=False
        self.assertFalse(DOCTOR.served_php_probe(self.php_server(payload,503))['available'])
    def test_slow_headers_obey_absolute_probe_deadline(self):
        started=time.monotonic();value=DOCTOR.served_php_probe(self.php_server({},slow=True),.15)
        self.assertFalse(value['available']);self.assertLess(time.monotonic()-started,.6)
    def test_each_probe_deadline_remains_bound_to_its_own_socket(self):
        payload=json.dumps(self.php_payload()).encode()
        class Socket:
            def __init__(self):self.shutdowns=0;self.closes=0
            def shutdown(self,unused):self.shutdowns+=1
            def close(self):self.closes+=1
            def settimeout(self,unused):pass
        class Response:
            def __init__(self,status,body=b''):self.status=status;self.body=body
            def read(self,unused):return self.body
            def close(self):pass
        class Connection(DOCTOR.web_readiness.LoopbackHTTP):
            def __init__(self,response):
                super().__init__('127.0.0.1',8001,.8,time.monotonic()+4)
                self.sock=Socket();self._owned_sockets=[self.sock];self.response=response
            def connect(self):pass
            def request(self,*unused,**ignored):pass
            def getresponse(self):return self.response
            def close(self):pass
        class Timer:
            instances=[]
            def __init__(self,unused,callback):self.callback=callback;self.daemon=False;self.cancelled=False;self.instances.append(self)
            def start(self):pass
            def cancel(self):self.cancelled=True
        connections=[Connection(Response(404)),Connection(Response(200,payload))]
        with patch.object(DOCTOR.web_readiness,'LoopbackHTTP',side_effect=connections),patch.object(DOCTOR.threading,'Timer',Timer):
            value=DOCTOR.served_php_probe([
                ('http','127.0.0.1',8001,'first.example.test'),
                ('http','127.0.0.1',8002,'second.example.test'),
            ])
        self.assertTrue(value['ok'])
        before=[(connection.sock.shutdowns,connection.sock.closes) for connection in connections]
        Timer.instances[0].callback()
        self.assertEqual((connections[0].sock.shutdowns,connections[0].sock.closes),(before[0][0]+1,before[0][1]+1))
        self.assertEqual((connections[1].sock.shutdowns,connections[1].sock.closes),before[1])
    def test_parsed_vhosts_change_headers_and_ports_without_public_resolution(self):
        targets=DOCTOR.served_php_targets('*:8443 pbx.example.test (/etc/apache2/pbx.conf:1)\n port 9443 namevhost secondary.example.test (/etc/apache2/secondary:1)\n[::]:8080 ipv6.example.test (/etc/apache2/ipv6:1)')
        self.assertEqual(targets[0],('https','127.0.0.1',8443,'pbx.example.test'))
        self.assertTrue(any(row[1]=='::1' and row[2]==8080 for row in targets))
        self.assertTrue(all(row[1] in ('127.0.0.1','::1') for row in targets))
    def test_process_output_and_deadline_bounds_apply_before_capture_completes(self):
        status,output=DOCTOR.command(['/usr/bin/python3','-I','-c','import os\nwhile True:os.write(1,b"x"*65536)'],.5)
        self.assertEqual((status,output),(125,''))
        started=time.monotonic();status,output=DOCTOR.command(['/usr/bin/python3','-I','-c','import time;time.sleep(20)'],.1)
        self.assertEqual((status,output),(124,''));self.assertLess(time.monotonic()-started,.8)
    def test_exited_probe_parent_does_not_leave_its_stdout_holding_descendant(self):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'child-pid'
            code='import os,time\nif os.fork():os._exit(0)\nopen('+repr(str(path))+',"w").write(str(os.getpid()))\ntime.sleep(20)'
            self.assertEqual(DOCTOR.command(['/usr/bin/python3','-I','-c',code],.2),(124,''))
            self.assert_process_retired(int(path.read_text()))
    def test_collector_probe_preserves_freshness_failures_and_excludes_arbitrary_detail(self):
        with patch.object(DOCTOR,'protected',return_value=True),patch.object(DOCTOR,'command',return_value=(0,json.dumps({'ok':True,'connected':True,'heartbeat_age_seconds':1.5,'active_batches':2,'reserved_contacts':3,'detail':'must-not-appear'}))):
            value=DOCTOR.collector_probe();self.assertTrue(value['ok']);self.assertNotIn('must-not-appear',json.dumps(value))
        for age in [16,-1,float('nan'),'1']:
            with patch.object(DOCTOR,'protected',return_value=True),patch.object(DOCTOR,'command',return_value=(0,json.dumps({'ok':True,'connected':True,'heartbeat_age_seconds':age,'active_batches':0,'reserved_contacts':0}))):
                self.assertFalse(DOCTOR.collector_probe()['ok'])
        with patch.object(DOCTOR,'protected',return_value=True),patch.object(DOCTOR,'command',return_value=(1,json.dumps({'ok':False,'failure_code':'phone_event_collector_stale','detail':'must-not-appear'}))):
            value=DOCTOR.collector_probe();self.assertEqual(value['failure_code'],'phone_event_collector_stale');self.assertNotIn('detail',value)
    def test_root_collector_probe_uses_deep_budget_without_extending_web_or_freshness(self):
        health={'ok':True,'connected':True,'heartbeat_age_seconds':1.5,'active_batches':0,'reserved_contacts':0}
        with patch.object(DOCTOR.os,'geteuid',return_value=0),patch.object(DOCTOR,'protected',return_value=True):
            for budget,seconds in [('quick',2),('deep',15)]:
                with self.subTest(budget=budget),patch.object(DOCTOR,'command',return_value=(0,json.dumps(health))) as command, \
                     patch.object(DOCTOR.time,'monotonic',side_effect=[10,11]):
                    value=DOCTOR.collector_probe(budget=budget)
                    self.assertTrue(value['ok']);self.assertEqual(value['heartbeat_age_seconds'],2.5)
                    self.assertEqual(command.call_args.args[1],seconds)
                with patch.object(DOCTOR,'command',return_value=(124,'')):
                    self.assertEqual(DOCTOR.collector_probe(budget=budget)['failure_code'],'phone_collector_probe_timeout')
            with patch.object(DOCTOR,'command',return_value=(0,json.dumps(dict(health,heartbeat_age_seconds=14)))), \
                 patch.object(DOCTOR.time,'monotonic',side_effect=[10,12]):
                self.assertEqual(DOCTOR.collector_probe(budget='deep')['failure_code'],'phone_event_collector_stale')
        with patch.object(DOCTOR.os,'geteuid',return_value=pwd.getpwnam('asterisk').pw_uid), \
             patch.object(DOCTOR,'command',side_effect=AssertionError('No unauthorized deep probe')):
            with self.assertRaises(ValueError):DOCTOR.collector_probe(budget='deep')
    def test_finite_collector_work_beyond_quick_limit_completes_for_root_and_reaps_quick_child(self):
        original=DOCTOR.command
        prefix=['/usr/bin/env','-u','GITHUB_TOKEN','-u','GH_TOKEN','-u','SLS_MASS_NOTIFY_GITHUB_TOKEN','/usr/sbin/runuser','-u','asterisk','--']
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);pid=root/'pid';helper=root/'sls_phone_events.py'
            health={'ok':True,'connected':True,'heartbeat_age_seconds':0.1,'active_batches':0,'reserved_contacts':0}
            helper.write_text('import os,time\nfrom pathlib import Path\nPath('+repr(str(pid))+').write_text(str(os.getpid()))\ntime.sleep(2.15)\nprint('+repr(json.dumps(health))+')\n')
            def dispatch(argv,seconds):
                self.assertEqual(argv[:-4],prefix)
                # Privilege-transition argv has a separate contract; this
                # finite process tests the actual command deadline/retirement.
                return original(argv[-4:],seconds)
            with patch.object(DOCTOR.os,'geteuid',return_value=0),patch.object(DOCTOR,'RUNTIME',root), \
                 patch.object(DOCTOR,'protected',return_value=True),patch.object(DOCTOR,'command',side_effect=dispatch):
                self.assertEqual(DOCTOR.collector_probe()['failure_code'],'phone_collector_probe_timeout')
                child=int(pid.read_text())
                with self.assertRaises(ProcessLookupError):os.kill(child,0)
                self.assertTrue(DOCTOR.collector_probe(budget='deep')['ok'])
    def collector_report_with_finite_wait(self, age, *, resource_wait=0, state_wait=0, initial=None, refresh=None, native_probe=None, resource_effect=None, budget="deep"):
        ready=threading.Event();calls=[];original_command=DOCTOR.command
        health={'ok':True,'connected':True,'heartbeat_age_seconds':age,'active_batches':0,'reserved_contacts':0}
        samples=[dict(health) if initial is None else initial,
                 {'ok':False,'connected':False,'failure_code':'phone_event_collector_stale'} if refresh is None else refresh]
        def collector(*,budget):
            self.assertLess(len(calls),2,'A diagnostic must never loop over collector refreshes')
            calls.append(budget)
            value=native_probe(budget=budget) if native_probe else dict(samples[len(calls)-1])
            ready.set()
            return value
        def resources(*args,**kwargs):
            self.assertTrue(ready.wait(1),'Concurrent collector did not finish before the finite resource observation')
            time.sleep(resource_wait)
            if resource_effect:resource_effect()
            return {'ok':True}
        def state():
            time.sleep(state_wait)
            return {'ok':True,'unfinished':[],'unsafe_evidence':False,'latest_transaction':None,'last_failure':None,'root_required':False}
        def command(args,*limits):
            if native_probe and args[-1]=='--health':return original_command(args,*limits)
            return (0,'Asterisk 20.18.2') if args[0]=='/usr/sbin/asterisk' else (0,'active')
        versions={'framework':'17.0.33.2','dashboard':'17.0.5','slsmassnotifyserver':'0.2.0-beta'}
        with patch.object(DOCTOR.os,'geteuid',return_value=0), \
             patch.object(DOCTOR,'bounded',return_value=b'ID=debian\nVERSION_ID=12\n'), \
             patch.object(DOCTOR,'module_version',side_effect=lambda path,name:versions[name]), \
             patch.object(DOCTOR,'REQUIRED_PATHS',()),patch.object(DOCTOR,'command',side_effect=command), \
             patch.object(DOCTOR,'served_php_local',return_value={'ok':True}), \
             patch.object(DOCTOR,'freepbx_gui_local',return_value={'ok':True}), \
             patch.object(DOCTOR,'collector_probe',side_effect=collector), \
             patch.object(DOCTOR,'release_probe',return_value={'ok':True}), \
             patch.object(DOCTOR,'resource_probe',side_effect=resources), \
             patch.object(DOCTOR,'installation_state',side_effect=state):
            value=DOCTOR.report(budget=budget)
        row=next(item for item in value['checks'] if item['code']=='authenticated_collector')
        self.assertTrue(all(item['ok'] for item in value['checks'] if item is not row))
        self.assertEqual(len(value['checks']),16)
        self.assertEqual([item['code'] for item in value['checks']].index('authenticated_collector'),12)
        return value,row,calls

    def test_report_cannot_publish_a_collector_sample_that_expired_while_other_probes_ran(self):
        value,row,calls=self.collector_report_with_finite_wait(14.9,resource_wait=.25)
        self.assertFalse(row['ok'],'A fast collector observation expired during the real concurrent wait but still passed')
        self.assertEqual(row['observed']['failure_code'],'phone_event_collector_stale')
        self.assertFalse(value['ok']);self.assertEqual(calls,['deep','deep'])

    def test_report_rechecks_collector_freshness_after_late_recovery_evidence_inspection(self):
        value,row,calls=self.collector_report_with_finite_wait(14.9,state_wait=.25)
        self.assertFalse(row['ok'],'Late report composition emitted a stale authenticated collector PASS')
        self.assertEqual(row['observed']['failure_code'],'phone_event_collector_stale')
        self.assertFalse(value['ok']);self.assertEqual(calls,['deep','deep'])

    def test_report_keeps_a_genuinely_fresh_collector_healthy_and_hides_private_timing(self):
        value,row,calls=self.collector_report_with_finite_wait(.25,resource_wait=.25)
        self.assertTrue(row['ok']);self.assertTrue(value['ok'])
        self.assertGreaterEqual(row['observed']['heartbeat_age_seconds'],.4)
        self.assertLessEqual(row['observed']['heartbeat_age_seconds'],15)
        self.assertEqual(set(row['observed']),{'ok','connected','heartbeat_age_seconds','active_batches','reserved_contacts'})

    def test_report_refreshes_only_an_initially_healthy_expired_observation(self):
        fresh={'ok':True,'connected':True,'heartbeat_age_seconds':.1,'active_batches':0,'reserved_contacts':0}
        for budget in ('quick','deep'):
            with self.subTest(budget=budget):
                value,row,calls=self.collector_report_with_finite_wait(14.9,resource_wait=.25,refresh=fresh,budget=budget)
                self.assertTrue(value['ok']);self.assertTrue(row['ok'])
                self.assertEqual(calls,[budget,budget])
                self.assertEqual(set(row['observed']),set(fresh))

    def test_report_failed_or_expired_refresh_never_reuses_the_old_pass(self):
        for code in ('phone_event_collector_stale','phone_collector_health_invalid','phone_collector_probe_timeout'):
            with self.subTest(code=code):
                value,row,calls=self.collector_report_with_finite_wait(14.9,resource_wait=.25,
                    refresh={'ok':False,'connected':False,'failure_code':code})
                self.assertFalse(value['ok']);self.assertFalse(row['ok'])
                self.assertEqual(row['observed']['failure_code'],code)
                self.assertEqual(calls,['deep','deep'])
        value,row,calls=self.collector_report_with_finite_wait(14.9,resource_wait=.25,
            refresh={'ok':True,'connected':True,'heartbeat_age_seconds':15.0,'active_batches':0,'reserved_contacts':0})
        self.assertFalse(row['ok']);self.assertEqual(calls,['deep','deep'])

    def test_report_does_not_retry_or_promote_an_initial_collector_failure(self):
        fresh={'ok':True,'connected':True,'heartbeat_age_seconds':.1,'active_batches':0,'reserved_contacts':0}
        for code in ('phone_event_collector_stale','phone_collector_health_invalid','phone_collector_probe_timeout'):
            with self.subTest(code=code):
                value,row,calls=self.collector_report_with_finite_wait(0,resource_wait=.05,
                    initial={'ok':False,'failure_code':code},refresh=fresh)
                self.assertFalse(value['ok']);self.assertFalse(row['ok'])
                self.assertEqual(row['observed']['failure_code'],code);self.assertEqual(calls,['deep'])

    def test_report_observes_a_real_advancing_private_heartbeat_after_slow_resource_work(self):
        actual_probe=DOCTOR.collector_probe
        with tempfile.TemporaryDirectory(prefix='sls-report-heartbeat-',dir='/run') as name:
            runtime=Path(name);runtime.chmod(0o755);heartbeat=runtime/'heartbeat'
            heartbeat.write_text(str(time.time()-12));heartbeat.chmod(0o644)
            helper=runtime/'sls_phone_events.py'
            helper.write_text('import json,time,sys\nfrom pathlib import Path\nage=time.time()-float(Path(__file__).with_name("heartbeat").read_text())\nvalue={"ok":True,"connected":True,"heartbeat_age_seconds":age,"active_batches":0,"reserved_contacts":0} if age<=15 else {"ok":False,"failure_code":"phone_event_collector_stale"}\nprint(json.dumps(value));sys.exit(0 if value["ok"] else 1)\n');helper.chmod(0o644)
            with patch.object(DOCTOR,'RUNTIME',runtime):
                value,row,calls=self.collector_report_with_finite_wait(0,resource_wait=3.3,
                    native_probe=actual_probe,resource_effect=lambda:heartbeat.write_text(str(time.time())))
            self.assertTrue(value['ok']);self.assertTrue(row['ok']);self.assertEqual(calls,['deep','deep'])
            self.assertLess(row['observed']['heartbeat_age_seconds'],15)
            self.assertNotIn('_observed_at',json.dumps(value))

    def test_nonroot_trust_check_cannot_execute_protected_privileged_verification(self):
        with patch.object(DOCTOR.os,'geteuid',return_value=pwd.getpwnam('asterisk').pw_uid),patch.object(DOCTOR,'command',side_effect=AssertionError('Unexpected trust command')):
            self.assertEqual(DOCTOR.release_probe()['failure_code'],'release_trust_root_inspection_required')
    def test_real_publisher_and_installed_inventory_verification_is_read_only(self):
        self._check_real_publisher_inventory('slsmassnotifyserver-0.1.6-beta')

    def test_v_tag_publisher_inventory_remains_authenticated_and_read_only(self):
        try:
            self._check_real_publisher_inventory('v0.1.6-beta')
        except Exception as error:
            if type(error).__name__ != 'TrustError':
                raise
            self.fail('A valid signed v-tag inventory was rejected: '+str(error))

    def test_exact_uppercase_current_inventory_remains_authenticated_and_read_only(self):
        self._check_real_publisher_inventory('V0.1.9-beta','0.1.9-beta')

    def test_exact_reserved_release_alias_inventory_is_authenticated_and_read_only(self):
        self._check_real_publisher_inventory('release-0.1.9-beta','0.1.9-beta')

    def test_other_release_alias_inventories_are_not_enrolled(self):
        for tag,version in [('release-0.1.10-beta','0.1.10-beta'),('release-0.1.8-beta','0.1.8-beta'),('Release-0.1.9-beta','0.1.9-beta'),('release-0.1.09-beta','0.1.9-beta')]:
            with self.subTest(tag=tag),self.assertRaises(Exception) as failure:self._check_real_publisher_inventory(tag,version)
            self.assertEqual(type(failure.exception).__name__,'TrustError')

    def test_uppercase_other_inventory_is_not_enrolled(self):
        with self.assertRaises(Exception) as failure:
            self._check_real_publisher_inventory('V0.1.10-beta','0.1.10-beta')
        self.assertEqual(type(failure.exception).__name__,'TrustError')

    def _check_real_publisher_inventory(self, release_tag, version='0.1.6-beta'):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);runtime=root/'runtime';runtime.mkdir(mode=0o700);web=root/'web';web.mkdir(mode=0o700)
            key=root/'private-key'
            subprocess.run(['openssl','genpkey','-algorithm','Ed25519','-out',str(key)],check=True,capture_output=True)
            public=subprocess.run(['openssl','pkey','-in',str(key),'-pubout'],check=True,capture_output=True).stdout
            source=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py').read_text()
            source=re.sub(r'^PUBLIC_KEY = .*$',lambda unused:'PUBLIC_KEY = '+repr(public),source,flags=re.M)
            (runtime/'sls_module_trust.py').write_text(source)
            (runtime/'sls_release_trust.py').write_bytes((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_release_trust.py').read_bytes())
            for path in runtime.iterdir():path.chmod(0o600)
            trust=load('doctor_signed_trust_fixture',runtime/'sls_module_trust.py');store=root/'trust'
            body=('<module><rawname>slsmassnotifyserver</rawname><version>'+version+'</version></module>').encode()
            archive=root/('slsmassnotifyserver-'+version+'.tgz')
            with tarfile.open(archive,'w:gz') as package:
                member=tarfile.TarInfo('slsmassnotifyserver/module.xml');member.size=len(body);package.addfile(member,io.BytesIO(body))
            manifest=root/'release-manifest.json';signature=root/'release-manifest.sig'
            archive_sha=hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest.write_text(json.dumps({'schema':1,'version':version,'tag':release_tag,
                'package':archive.name,'package_sha256':archive_sha,'installer_sha256':'a'*64}))
            subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(manifest),'-out',str(signature)],check=True,capture_output=True)
            generation=store/trust.enroll_sls(store,archive,manifest,signature)
            installed=web/'admin/modules/slsmassnotifyserver/module.xml';installed.parent.mkdir(mode=0o700,parents=True);installed.write_bytes(body)
            for module in ('framework','dashboard'):
                target=web/'admin/modules'/module/'module.xml';target.parent.mkdir(mode=0o700);target.write_text('<module>'+module+'</module>')
                inventory=root/(module+'-reviewed.json')
                inventory.write_text(json.dumps({'schema':1,'module':module,'version':'17.0.1','source':{'kind':'reviewed-upstream-and-overlays','archive_sha256':'b'*64},
                    'files':{'module.xml':{'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'target':'admin/modules/'+module+'/module.xml'}}}))
                inventory.chmod(0o600);trust.enroll_reviewed(store,inventory,hashlib.sha256(inventory.read_bytes()).hexdigest())
            def snapshot():
                return {str(path.relative_to(root)):(path.read_bytes(),path.stat().st_mode,path.stat().st_ino,path.stat().st_mtime_ns)
                        for tree in (runtime,web,store) for path in tree.rglob('*') if path.is_file()}
            with patch.object(DOCTOR,'RUNTIME',runtime),patch.object(DOCTOR,'TRUST_ROOT',store),patch.object(DOCTOR,'WEB_ROOT',web),patch.object(DOCTOR,'protected',return_value=True):
                before=snapshot();value=DOCTOR.release_probe()
                self.assertTrue(value['ok']);self.assertTrue(value['publisher_authenticated']);self.assertEqual(value['package_sha256'],archive_sha)
                self.assertEqual(snapshot(),before)
                stock=web/'admin/modules/dashboard/module.xml';stock.write_bytes(b'changed')
                value=DOCTOR.release_probe();self.assertFalse(value['ok']);self.assertTrue(value['publisher_authenticated']);self.assertFalse(value['stock_inventories']['dashboard'])
                installed.write_bytes(b'changed')
                self.assertEqual(DOCTOR.release_probe()['failure_code'],'release_trust_or_inventory_invalid')
                installed.write_bytes(body);(generation/'release-manifest.sig').write_bytes(b'0'*64)
                self.assertEqual(DOCTOR.release_probe()['failure_code'],'release_trust_or_inventory_invalid')
    def test_journal_stage_is_redacted_and_old_failure_remains_historical(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);journal=root/'journal';journal.mkdir();data=root/'data';data.mkdir()
            directory=journal/('transaction-'+'a'*24);directory.mkdir()
            now=int(time.time());path=directory/'transaction.json'
            path.write_text(json.dumps({'schema':1,'phase':'committed','updated_at':now,'stage':'post-install verification','stage_at':now,'settings':{'SECRET':'must-not-appear'}}))
            (data/'install-failure.json').write_text(json.dumps({'stage':'module activation','failed_at':'2001-01-01T00:00:00+00:00','error_category':'install_command_failed','solution':'must-not-appear','log':'must-not-appear'}))
            with patch.object(DOCTOR,'JOURNAL',journal),patch.object(DOCTOR,'DATA',data),patch.object(DOCTOR,'protected',return_value=True):
                value=DOCTOR.installation_state();self.assertTrue(value['ok']);self.assertEqual(value['latest_transaction']['stage'],'post-install verification')
                self.assertTrue(value['last_failure']['historical_only']);self.assertTrue(value['last_failure']['superseded_by_commit']);self.assertNotIn('must-not-appear',json.dumps(value))
                row=json.loads(path.read_text());row['stage']='must-not-appear';path.write_text(json.dumps(row))
                self.assertTrue(DOCTOR.installation_state()['unsafe_evidence'])
    def test_vm_requires_explicit_disposable_opt_in_before_loading_any_image(self):
        for baseline in ('fresh', '0.1.8-beta'):
            with self.subTest(baseline=baseline):
                result=subprocess.run(['python3','-I',str(ROOT/'tools/qualify_installer_vm.py'),'--image','/nonexistent','--image-sha256','a'*64,'--bundle','/nonexistent','--baseline',baseline,'--report','/nonexistent'],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn('Explicit --allow-disposable-vm is required',result.stderr)

    def test_module_identity_rejects_multibyte_document_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'module.xml'
            for encoding in ('utf-8', 'utf-16', 'utf-16-le', 'utf-16-be'):
                xml_encoding={'utf-16-le':'UTF-16LE', 'utf-16-be':'UTF-16BE'}.get(encoding,encoding)
                for declaration in ('', '<!DOCTYPE module [<!ENTITY version "0.1.8-beta">]>'):
                    with self.subTest(encoding=encoding, declaration=bool(declaration)):
                        version='&version;' if declaration else '0.1.8-beta'
                        path.write_bytes(('<?xml version="1.0" encoding="'+xml_encoding+'"?>'+declaration+'<module><rawname>slsmassnotifyserver</rawname><version>'+version+'</version></module>').encode(encoding))
                        self.assertEqual(DOCTOR.module_version(path,'slsmassnotifyserver'),None if declaration else '0.1.8-beta')


class DisposableVmScenarios(unittest.TestCase):
    def test_purge_scenario_uses_the_documented_uninstaller_environment(self):
        class Guest:
            def __init__(self): self.commands=[]
            def start(self): pass
            def copy(self, bundle): pass
            def ssh(self, command, **options):
                self.commands.append(command)
                output='fresh\n' if 'xml.etree.ElementTree' in command else '{}'
                return subprocess.CompletedProcess(command,0,stdout=output,stderr='')
        with tempfile.TemporaryDirectory() as temporary:
            bundle=Path(temporary)
            (bundle/'slsmassnotifyserver-0.1.9-beta.tgz').touch()
            for name in ('uninstall','purge'):
                with self.subTest(scenario=name):
                    guest=Guest()
                    result=VM.scenario(guest,bundle,name,'fresh',{})
                    self.assertTrue(result['ok'])
                    commands=[row for row in guest.commands if 'sls_mass_notify_uninstall.sh' in row]
                    expected='bash /usr/local/bin/sls_mass_notify/sls_mass_notify_uninstall.sh'
                    if name=='purge': expected='SLS_MASS_NOTIFY_PURGE_CONFIG=1 '+expected
                    self.assertEqual(commands,[expected])
                    reloads = [row for row in guest.commands if 'fwconsole' in row]
                    self.assertEqual(reloads, ['/usr/sbin/runuser -u asterisk -- /usr/sbin/fwconsole reload'] * 2,
                        'Disposable qualification must run the same unprivileged native reload as the installer')


class OfflineBundle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','Ed25519','-out',str(self.key)],check=True,capture_output=True)
        public=subprocess.run(['openssl','pkey','-in',str(self.key),'-pubout'],check=True,capture_output=True).stdout
        self.patch=patch.object(BUNDLE,'ANCHOR',public);self.patch.start();self.addCleanup(self.patch.stop)
        self.directory=self.root/'bundle';self.directory.mkdir(mode=0o700)
        self.installer=self.directory/'install_release.sh';self.installer.write_bytes(b'#!/bin/bash\nexit 0\n')
        self.package=self.directory/'slsmassnotifyserver-0.1.6-beta.tgz'
        with tarfile.open(self.package,'w:gz') as archive:
            body=b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.6-beta</version></module>'
            member=tarfile.TarInfo('slsmassnotifyserver/module.xml');member.size=len(body);archive.addfile(member,io.BytesIO(body))
        self.sign()
    def sign(self):
        manifest={'schema':1,'version':'0.1.6-beta','package':self.package.name,
            'installer_sha256':hashlib.sha256(self.installer.read_bytes()).hexdigest(),
            'package_sha256':hashlib.sha256(self.package.read_bytes()).hexdigest()}
        path=self.directory/'release-manifest.json';path.write_text(json.dumps(manifest))
        signature=self.directory/'release-manifest.sig'
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(path),'-out',str(signature)],check=True,capture_output=True)
        for entry in self.directory.iterdir():entry.chmod(0o600)
    def test_installer_package_signature_and_tampering(self):
        self.assertEqual(BUNDLE.release(self.directory)['version'],'0.1.6-beta')
        self.installer.write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError,'differs'):BUNDLE.release(self.directory)
        self.installer.write_bytes(b'#!/bin/bash\nexit 0\n');self.package.write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError,'differs'):BUNDLE.release(self.directory)
    def test_offline_environment_retains_the_authenticated_digest_and_clears_remote_url(self):
        values=BUNDLE.installer_environment(self.directory)
        self.assertEqual(values['SLS_MASS_NOTIFY_SHA256'],hashlib.sha256(self.package.read_bytes()).hexdigest())
        self.assertEqual(values['SLS_MASS_NOTIFY_TGZ_URL'],'')
        self.assertEqual(values['SLS_MASS_NOTIFY_TGZ'],str(self.package))
        self.installer.write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError,'differs'):BUNDLE.installer_environment(self.directory)
    def test_unsigned_and_publicly_writable_inputs_are_rejected(self):
        (self.directory/'release-manifest.sig').write_bytes(b'0'*64)
        with self.assertRaises(subprocess.CalledProcessError):BUNDLE.release(self.directory)
        self.sign();self.installer.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'Unsafe'):BUNDLE.release(self.directory)
    def test_symlinks_and_archive_traversal_are_rejected(self):
        self.installer.unlink();self.installer.symlink_to(self.key)
        with self.assertRaises(OSError):BUNDLE.release(self.directory)
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as archive:
            member=tarfile.TarInfo('slsmassnotifyserver/../../etc/passwd');member.size=1;archive.addfile(member,io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError,'Unsafe'):BUNDLE.members(data.getvalue(),'slsmassnotifyserver')


if __name__=='__main__':unittest.main()
