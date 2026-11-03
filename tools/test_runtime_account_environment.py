#!/usr/bin/python3
"""Check actual privilege-transition prefixes with inert private worker tails."""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or any(
    os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in
    (None, '', os.readlink('/proc/self/ns/' + kind))
    for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]
):
    raise SystemExit('Use the private fixture runner; no account-transition helpers were run.')

ROOT=Path(__file__).resolve().parents[1]
TOKENS=(
    'GITHUB_TOKEN','GH_TOKEN','SLS_MASS_NOTIFY_GITHUB_TOKEN',
    'AWS_SECRET_ACCESS_KEY','DATABASE_URL','SMTP_PASSWORD',
    'AZURE_CLIENT_SECRET','GOOGLE_APPLICATION_CREDENTIALS','KUBECONFIG',
    'MYSQL_PWD','PGPASSWORD','REDIS_URL','SSH_AUTH_SOCK',
    # PYTHONPATH is inert under the production Python ``-I`` boundary.
    # PHP_INI_SCAN_DIR cannot be used as a synthetic credential: PHP consumes
    # it before the worker has an opportunity to execute its re-exec boundary.
    'PYTHONPATH',
    'HTTP_PROXY','HTTPS_PROXY','NO_PROXY',
)


class RuntimeEnvironment(unittest.TestCase):
    def test_installer_runtime_child_receives_only_fixed_and_required_transaction_environment(self):
        required={
            'CONFIG_PATH':'/run/fixture/config.json',
            'SLS_CONFIG_CRYPTO_PHP':'/run/fixture/config-crypto.php',
            'SLS_INIT_DEPLOYMENT_PROFILE':'lite', 'SLS_INIT_PHONE_CAPACITY':'25',
            'SLS_MASS_NOTIFY_MODULE':'slsmassnotifyserver',
            'SLS_NATIVE_INSTALL_ACTION':'install', 'SLS_NATIVE_INSTALL_MODULE':'slsmassnotifyserver',
            'SLS_NATIVE_REGISTRY_MODULE':'dashboard', 'SLS_RECOVERY_AMI_NAMES':'["sll-module"]',
            'SLS_MASS_NOTIFY_DEFER_SIGNING':'1', 'SLS_MASS_NOTIFY_PRESERVE_PENDING':'1',
        }
        fixed={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'HOME':'/var/lib/asterisk','USER':'asterisk','LOGNAME':'asterisk',
               'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
        with tempfile.TemporaryDirectory(prefix='sls-installer-clean-env-',dir='/run') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            child=folder/'harmless-child.py'
            child.write_text('import json,os;print(json.dumps({"uid":os.geteuid(),"cwd":os.getcwd(),"environment":dict(os.environ)}))\n');child.chmod(0o644)
            for label,inputs,explicit in (
                ('required',required,{}), ('unset',{},{}), ('set-empty',{'CONFIG_PATH':''},{}),
                ('explicit-env',required,{'ORT_DISABLE_TELEMETRY':'1','PHP_INI_SCAN_DIR':'/etc/php/8.2/apache2/conf.d'}),
            ):
                with self.subTest(case=label):
                    arguments=['/usr/bin/python3','-I',str(child)]
                    if explicit:arguments=['/usr/bin/env',*[name+'='+value for name,value in explicit.items()],*arguments]
                    command='source "$1"; shift; sls_as_asterisk "$@"; [[ "$AWS_SECRET_ACCESS_KEY" = SLS_PRIVATE_BOUNDARY_FIXTURE ]]'
                    environment={**self.environment,**inputs,'HOME':'/private/root-home','USER':'root','LOGNAME':'root',
                                 'SLS_UNLISTED_PRIVATE_VALUE':'private fixture','ORT_DISABLE_TELEMETRY':'0',
                                 'PHP_INI_SCAN_DIR':'/private/root-php-config'}
                    result=subprocess.run(['/bin/bash','-c',command,'fixture',str(ROOT/'tools/install_release.sh'),*arguments],
                        env=environment,cwd=folder,capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertEqual(result.stderr,'')
                    value=json.loads(result.stdout)
                    self.assertEqual((value['uid'],value['cwd']),(self.expected_uid,'/'))
                    self.assertEqual(value['environment'],{**fixed,**inputs,**explicit})

    def test_private_root_working_directory_never_reaches_runtime_cli_children(self):
        with tempfile.TemporaryDirectory(prefix='sls-cli-private-cwd-',dir='/run') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            private=folder/'root-private';private.mkdir(mode=0o700)
            (private/'relative-parent-marker').write_text('preserved parent directory')
            observations=folder/'cwd-observations.jsonl';observations.touch();observations.chmod(0o666)
            probe=folder/'asterisk-probe'
            probe.write_text('#!/usr/bin/python3\nimport json,os,sys\n'
                'value={"uid":os.geteuid(),"cwd":os.getcwd(),"args":sys.argv[1:]}\n'
                'with open('+repr(str(observations))+',"a") as output:output.write(json.dumps(value)+"\\n")\n'
                'if not os.access(".",os.X_OK):print("Unable to access running directory; changing to /",file=sys.stderr)\n'
                'print("0 results found." if sys.argv[-1]=="database show DEVICE" else json.dumps(value))\n')
            probe.chmod(0o755)
            subprocess.run(['/usr/bin/mount','--bind',str(probe),'/usr/sbin/asterisk'],check=True,timeout=5)
            try:
                for script in ('tools/install_release.sh','tools/uninstall_release.sh'):
                    with self.subTest(script=script):
                        command='source "$1"; initial="$PWD"; asterisk -rx "core show version" relative-argument; [[ "$PWD" = "$initial" ]] && [[ "$(cat relative-parent-marker)" = "preserved parent directory" ]]'
                        result=subprocess.run(['/bin/bash','-c',command,'fixture',str(ROOT/script)],cwd=private,
                            capture_output=True,text=True,env=self.environment,timeout=10)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        self.assertEqual(result.stderr,'')
                        value=json.loads(result.stdout)
                        self.assertEqual(value['cwd'],'/')
                        self.assertEqual(value['args'],['-rx','core show version','relative-argument'])
                for name,call in (
                    ('sls_install_doctor.py', "status,raw=m['command'](['/usr/sbin/asterisk','-rx','core show version']); assert status==0; print(raw)"),
                    ('sls_install_idle.py', "print(m['channel_inventory']())"),
                    ('sls_resource_capacity.py', "import json; print(json.dumps(m['detect_internal_phones']()))"),
                ):
                    with self.subTest(helper=name):
                        program='import os,runpy,sys; initial=os.getcwd(); m=runpy.run_path(sys.argv[1]); '+call+'; assert os.getcwd()==initial'
                        result=subprocess.run([sys.executable,'-I','-c',program,str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify'/name)],cwd=private,
                            capture_output=True,text=True,env=self.environment,timeout=10)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        self.assertEqual(result.stderr,'')
                values=[json.loads(line) for line in observations.read_text().splitlines()]
                self.assertEqual(len(values),5)
                self.assertTrue(all(value['uid']==self.expected_uid and value['cwd']=='/' for value in values))
            finally:
                subprocess.run(['/usr/bin/umount','/usr/sbin/asterisk'],check=True,timeout=5)

    def setUp(self):
        if os.environ.get('SLS_TEST_NAMESPACE')!='entered':self.fail('Use tools/run_isolated_tests.sh')
        account=pwd.getpwnam('asterisk')
        self.expected_uid=account.pw_uid;self.expected_gid=account.pw_gid
        self.expected_groups=sorted(os.getgrouplist('asterisk',account.pw_gid))
        self.environment={
            'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
            **dict.fromkeys(TOKENS,'SLS_PRIVATE_BOUNDARY_FIXTURE'),
        }

    def test_installer_and_uninstaller_asterisk_cli_never_run_with_root_identity(self):
        with tempfile.TemporaryDirectory(prefix='sls-cli-account-',dir='/run') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            probe=folder/'asterisk-probe'
            probe.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"uid":os.geteuid(),"args":sys.argv[1:]}))\n')
            probe.chmod(0o755)
            # The runner verified private mount/PID/network namespaces before
            # this disposable bind. No real Asterisk binary is executed.
            subprocess.run(['/usr/bin/mount','--bind',str(probe),'/usr/sbin/asterisk'],check=True,timeout=5)
            try:
                for script in ('tools/install_release.sh','tools/uninstall_release.sh'):
                    with self.subTest(script=script):
                        result=subprocess.run(['/bin/bash','-c','source "$1"; asterisk -rx "core show version"',
                            'fixture',str(ROOT/script)],capture_output=True,text=True,env=self.environment,timeout=10)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        value=json.loads(result.stdout)
                        self.assertEqual(value['uid'],self.expected_uid)
                        self.assertEqual(value['args'],['-rx','core show version'])
                for name,call in (
                    ('sls_install_doctor.py', "status,raw=m['command'](['/usr/sbin/asterisk','-rx','core show version']); assert status==0; print(raw)"),
                    ('sls_install_idle.py', "print(m['channel_inventory']())"),
                ):
                    with self.subTest(helper=name):
                        program='import runpy,sys; m=runpy.run_path(sys.argv[1]); '+call
                        result=subprocess.run([sys.executable,'-I','-c',program,
                            str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify'/name)],
                            capture_output=True,text=True,env=self.environment,timeout=10)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        self.assertEqual(json.loads(result.stdout)['uid'],self.expected_uid)
            finally:
                subprocess.run(['/usr/bin/umount','/usr/sbin/asterisk'],check=True,timeout=5)

    def test_uninstaller_runtime_children_cannot_keep_maintenance_lease_descriptors(self):
        with tempfile.TemporaryDirectory(prefix='sls-uninstall-fds-',dir='/run') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            probe=folder/'probe.py'
            probe.write_text('import json,os; print(json.dumps({"uid":os.geteuid(),"fds":[os.readlink("/proc/self/fd/"+n) for n in os.listdir("/proc/self/fd") if n.isdigit() and int(n)>2 and os.path.exists("/proc/self/fd/"+n)]}))')
            probe.chmod(0o644)
            command='source "$1"; SLS_MASS_NOTIFY_MAINTENANCE_LOCK="$3"; exec {UNINSTALL_MAINTENANCE_LOCK_FD}>"$3"; run_as_asterisk /usr/bin/python3 -I "$2"'
            result=subprocess.run(['/bin/bash','-c',command,'fixture',str(ROOT/'tools/uninstall_release.sh'),str(probe),str(folder/'maintenance.lock')],
                capture_output=True,text=True,env=self.environment,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            value=json.loads(result.stdout)
            self.assertEqual(value['uid'],self.expected_uid)
            self.assertNotIn(str(folder/'maintenance.lock'),value['fds'])

    def test_installer_voice_checks_close_root_leases_and_disable_telemetry(self):
        with tempfile.TemporaryDirectory(prefix='sls-voice-boundary-',dir='/run') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            for name in ('piper/voices','sounds/tts'):
                (folder/name).mkdir(parents=True);(folder/name).chmod(0o777)
                (folder/name).parent.chmod(0o755)
            log=folder/'observations.jsonl';log.touch();log.chmod(0o666)
            private_bin=folder/'bin';private_bin.mkdir(mode=0o755);private_bin.chmod(0o755)
            probe=private_bin/'piper'
            probe.write_text('#!/usr/bin/python3\nimport json,os,sys,wave\n'
                'with open('+repr(str(log))+',"a") as out: out.write(json.dumps({"uid":os.geteuid(),"telemetry":os.environ.get("ORT_DISABLE_TELEMETRY"),"fds":[os.readlink("/proc/self/fd/"+n) for n in os.listdir("/proc/self/fd") if n.isdigit() and int(n)>2 and os.path.exists("/proc/self/fd/"+n)]})+"\\n")\n'
                'with wave.open(sys.argv[sys.argv.index("--output-file")+1],"wb") as out: out.setnchannels(1);out.setsampwidth(2);out.setframerate(8000);out.writeframes(b"\\0"*160)\n')
            probe.chmod(0o755)
            # Supply the whole private command directory. A fresh runner has
            # no installed Piper file to use as a bind-mount target, and the
            # read-only host command directory must never be populated here.
            subprocess.run(['/usr/bin/mount','--bind',str(private_bin),'/usr/local/bin'],check=True,timeout=5)
            try:
                command='source "$1"; DATA_DIR="$2"; INSTALL_LOG_OUTPUT="$2/log"; SLS_MASS_NOTIFY_MAINTENANCE_LOCK="$2/maintenance.lock"; sha256sum() { cat >/dev/null; }; exec {INSTALL_MAINTENANCE_LOCK_FD}>"$2/maintenance.lock"; verify_piper_voices'
                result=subprocess.run(['/bin/bash','-c',command,'fixture',str(ROOT/'tools/install_release.sh'),str(folder)],
                    capture_output=True,text=True,env={**self.environment,'ORT_DISABLE_TELEMETRY':'0'},timeout=15)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr+(folder/'log').read_text())
                observations=[json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(len(observations),3)
                for value in observations:
                    self.assertEqual(value['uid'],self.expected_uid)
                    self.assertEqual(value['telemetry'],'1')
                    self.assertNotIn(str(folder/'maintenance.lock'),value['fds'])
            finally:
                subprocess.run(['/usr/bin/umount','/usr/local/bin'],check=True,timeout=5)

    def test_php_worker_transitions_remove_inherited_environment(self):
        with tempfile.TemporaryDirectory(prefix='sls-root-worker-env-') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            shutil.copytree(ROOT/'slsmassnotifyserver/bin/sls_mass_notify',folder,dirs_exist_ok=True)
            cases=[('sls_mass_notify_cluster_worker.php','    // Installer acquires','--status',False),
                   ('sls_mass_notify_automation_worker.php','    $account=posix_getpwnam','--sources',False),
                   ('sls_mass_notify_announcement_worker.php','    $store = new SlsAnnouncementJobStore();','--health-check',True)]
            for name,marker,argument,shutdown in cases:
                with self.subTest(worker=name):
                    source=(ROOT/'slsmassnotifyserver/bin'/name).read_text(encoding='utf-8')
                    prefix=source.split(marker,1)[0]
                    if prefix==source:self.fail('Missing actual transition boundary')
                    tail='''$initial=(string)file_get_contents('/proc/self/environ');$present=false;
foreach('''+repr(list(TOKENS))+''' as $name){$present=$present||getenv($name)!==false||str_contains($initial,$name.'=');}
echo json_encode(['uid'=>posix_geteuid(),'gid'=>posix_getegid(),'groups'=>posix_getgroups(),'token_present'=>$present]),"\\n";
'''
                    if shutdown:tail+='$finished=true;\n'
                    tail+='exit(0); } catch(Throwable $error){fwrite(STDERR,"Private transition failed.\\n");exit(1);}\n'
                    script=folder/name;script.write_text(prefix+tail,encoding='utf-8');script.chmod(0o644)
                    result=subprocess.run(['/usr/bin/php',str(script),argument],env=self.environment,capture_output=True,text=True,timeout=5,check=False)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    value=json.loads(result.stdout);self.assertEqual(value['uid'],self.expected_uid);self.assertEqual(value['gid'],self.expected_gid)
                    self.assertEqual(sorted(value['groups']),self.expected_groups)
                    self.assertFalse(value['token_present'],'A root worker retained inherited caller variables after its account transition')

    def test_uninstaller_children_receive_clean_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary).chmod(0o755)
            probe=Path(temporary)/'probe.py';probe.write_text('import json,os; print(json.dumps({"uid":os.geteuid(),"gid":os.getegid(),"groups":os.getgroups(),"token_present":any(name in os.environ for name in '+repr(TOKENS)+')}))',encoding='utf-8');probe.chmod(0o644)
            # The script is sourced only to inspect child inheritance; main and
            # teardown functions are never called, and no PBX path is mutated.
            result=subprocess.run(['/bin/bash','-c','source "$1"; run_as_asterisk /usr/bin/python3 -I "$2"',
                'fixture',str(ROOT/'tools/uninstall_release.sh'),str(probe)],env=self.environment,capture_output=True,text=True,timeout=5,check=False)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value['uid'],self.expected_uid);self.assertEqual(value['gid'],self.expected_gid)
            self.assertEqual(sorted(value['groups']),self.expected_groups);self.assertFalse(value['token_present'])

    def test_speech_transition_removes_inherited_environment(self):
        with tempfile.TemporaryDirectory(prefix='sls-speech-root-env-') as temporary:
            folder=Path(temporary);folder.chmod(0o755)
            shutil.copytree(ROOT/'slsmassnotifyserver/bin/sls_mass_notify',folder,dirs_exist_ok=True)
            source=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_speech_admission.py').read_text(encoding='utf-8')
            marker="        admission = Admission(read_private_json('mass-notifications.config'), args.max_seconds or 1)"
            prefix=source.split(marker,1)[0]
            if prefix==source:self.fail('Missing actual speech privilege transition')
            tail='''        try:
            initial=Path('/proc/self/environ').read_bytes()
        except PermissionError:
            initial=b''
        print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups(),'token_present':any(name in os.environ or (name+'=').encode() in initial for name in '''+repr(TOKENS)+''')}))
        return 0
    except Exception:
        return 1
if __name__=='__main__':raise SystemExit(main())
'''
            script=folder/'sls_speech_admission.py';script.write_text(prefix+tail,encoding='utf-8');script.chmod(0o644)
            result=subprocess.run(['/usr/bin/python3','-I',str(script),'--reserve-media-bytes','1'],env=self.environment,capture_output=True,text=True,timeout=5,check=False)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value['uid'],self.expected_uid);self.assertEqual(value['gid'],self.expected_gid)
            self.assertEqual(sorted(value['groups']),self.expected_groups);self.assertFalse(value['token_present'])


if __name__=='__main__':unittest.main()
