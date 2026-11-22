#!/usr/bin/python3
"""Bound the real CLI's initial greeting on a private inert control socket."""
import os
import ast
import json
import fcntl
import shutil
import pwd
import signal
import select
import shlex
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]


class AsteriskCliDeadline(unittest.TestCase):
    script = 'tools/install_release.sh'

    def command(self, stall, uptime=False):
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-cli-greeting-') as name:
            base = Path(name)
            base.chmod(0o755)
            endpoint = base / 'control.sock'
            source = (ROOT / self.script).read_text()
            # Only the declared outer bound is shortened in this fixture.
            installer = base / 'installer.sh'
            source = source.replace('--kill-after=2 20 /usr/sbin/asterisk',
                                    '--kill-after=.1 .2 /usr/sbin/asterisk')
            if uptime:
                # Select only the inert socket; retain the actual state probe,
                # account transition and its production deadline handling.
                self.assertEqual(source.count("asterisk -rx 'core show uptime'"), 1)
                source = source.replace("asterisk -rx 'core show uptime'",
                                        'asterisk -s "$ASTERISK_DEADLINE_SOCKET" -rx \'core show uptime\'')
            installer.write_text(source)
            installer.chmod(0o644)
            connected = threading.Event()
            release = threading.Event()
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(endpoint))
            endpoint.chmod(0o666)
            server.listen(1)
            server.settimeout(4)

            def serve():
                try:
                    client, _ = server.accept()
                    with client:
                        connected.set()
                        if stall:
                            release.wait(2)
                except OSError:
                    pass

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            started = time.monotonic()
            try:
                operation = ('capture_pbx_running_state; printf "%s\\n" "$PBX_RUNNING"' if uptime
                             else 'asterisk -s "$2" -rx "core show version"')
                result = subprocess.run(['bash', '-c', 'ASTERISK_DEADLINE_SOCKET="$2"; source "$1"; ' + operation,
                    'fixture', str(installer), str(endpoint)], capture_output=True, text=True, timeout=4)
                result.elapsed = time.monotonic() - started
                self.assertTrue(connected.is_set(), 'Real native CLI did not reach the private socket')
                return result
            finally:
                release.set()
                server.close()
                worker.join(timeout=3)

    def test_initial_blocking_greeting_is_terminated_by_outer_deadline(self):
        result = self.command(True)
        self.assertIn(result.returncode, (124,137), result.stdout + result.stderr)
        self.assertLess(result.elapsed, 1.5, 'Initial greeting exceeded the fixture outer deadline')

    def test_immediate_native_connection_failure_keeps_its_exit_status(self):
        result = self.command(False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 124, result.stderr)
        self.assertLess(result.elapsed, 1.5)


class UninstallerAsteriskCliDeadline(AsteriskCliDeadline):
    script = 'tools/uninstall_release.sh'

    def test_stalled_uptime_probe_returns_unavailable_within_cli_bound(self):
        result = self.command(True, uptime=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), '0')
        self.assertLess(result.elapsed, 1.5, 'Uninstall uptime inspection exceeded its CLI deadline')

    def test_immediate_uptime_failure_keeps_pbx_unavailable(self):
        result = self.command(False, uptime=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), '0')
        self.assertLess(result.elapsed, 1.5)



class NativePbxWholeCommandDeadline(unittest.TestCase):
    """A native hook may call the real CLI without SLL's CLI wrapper."""
    def fixture(self, source_name, operation, *, immediate=None, stdin=False, invalid_uid=False, invalid_group=None):
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-pbx-command-') as name:
            base=Path(name);base.chmod(0o755)
            endpoint=base/'control.sock';connected=threading.Event();release=threading.Event()
            server=socket.socket(socket.AF_UNIX);server.bind(str(endpoint));endpoint.chmod(0o666);server.listen(1);server.settimeout(4)
            def serve():
                try:
                    connection,_=server.accept()
                    with connection:connected.set();release.wait(2)
                except OSError:pass
            thread=threading.Thread(target=serve,daemon=True)
            if immediate is None and not stdin:thread.start()
            marker=base/'account.json';marker.touch(mode=0o666);marker.chmod(0o666)
            cli='/usr/sbin/asterisk -s '+shlex.quote(str(endpoint))+' -rx '+shlex.quote('core show version')
            php='$args=$argv;file_put_contents('+json.dumps(str(marker))+',json_encode(["uid"=>posix_geteuid(),"token"=>getenv("GH_TOKEN"),"jit"=>ini_get("pcre.jit"),"args"=>$args]));'
            php+=('echo base64_encode(stream_get_contents(STDIN));exit(0);' if stdin else ('exit('+str(immediate)+');' if immediate is not None else 'passthru('+json.dumps(cli)+',$status);exit($status);'))
            native=base/'fwconsole';native.write_text('#!/usr/bin/php\n<?php\n'+php);native.chmod(0o755)
            installer=base/'entry.sh';source=(ROOT/source_name).read_text()
            # Only the declared whole-operation TERM/KILL fixture bounds change.
            source=source.replace('--kill-after=5 1200','--kill-after=.1 .2')
            installer.write_text(source);installer.chmod(0o644)
            target=Path('/usr/sbin/fwconsole').resolve(strict=False);mounted=False
            if not target.exists():
                self.assertEqual(target,Path('/var/lib/asterisk/bin/fwconsole'))
                target.parent.mkdir(parents=True,exist_ok=True);target.parent.chmod(0o755);target.touch(mode=0o755)
            try:
                subprocess.run(['mount','--bind',str(native),str(target)],check=True,capture_output=True);mounted=True
                prefix=('id() { printf 0; }; ' if invalid_uid else '')
                if invalid_group=='zero':prefix='id() { if [ "$1" = -g ]; then printf 0; else /usr/bin/id "$@"; fi; }; '
                elif invalid_group=='foreign':prefix='id() { if [ "$1" = -g ]; then printf 424242; else /usr/bin/id "$@"; fi; }; '
                code='source "$1"; '+prefix+operation
                completion_before=set(Path('/run').glob('sls-native-command-*'))
                before=time.monotonic()
                result=subprocess.run(['/bin/bash','-c',code,'fixture',str(installer),php],capture_output=True,text=True,timeout=4,env={**os.environ,'GH_TOKEN':'must-not-cross-runtime-boundary'})
                self.assertEqual(set(Path('/run').glob('sls-native-command-*')),completion_before,'Verified native completion left its private record behind')
                result.elapsed=time.monotonic()-before
                result.account=json.loads(marker.read_text()) if marker.stat().st_size else {}
                result.native_connected=connected.is_set()
                return result
            finally:
                release.set();server.close()
                if thread.ident is not None:thread.join(timeout=3)
                if mounted:subprocess.run(['umount',str(target)],check=True,capture_output=True)

    def test_deep_real_cli_stall_is_bounded_for_installer_and_uninstaller(self):
        for source,operation in [('tools/install_release.sh','fwconsole reload'),('tools/uninstall_release.sh','run_fwconsole reload')]:
            with self.subTest(source=source):
                result=self.fixture(source,operation)
                self.assertTrue(result.native_connected,'Native hook did not reach the real private Asterisk CLI')
                self.assertIn(result.returncode,(124,137),result.stdout+result.stderr)
                self.assertLess(result.elapsed,1.5,'Whole native hook bypassed the operation deadline')
                self.assertEqual(result.account.get('uid'),pwd.getpwnam('asterisk').pw_uid)
                self.assertFalse(result.account.get('token'))

    def test_healthy_and_native_failure_statuses_keep_real_account_and_arguments(self):
        for source,operation in [('tools/install_release.sh','fwconsole ma list'),('tools/uninstall_release.sh','run_fwconsole ma list')]:
            for status in (0,37):
                with self.subTest(source=source,status=status):
                    result=self.fixture(source,operation,immediate=status)
                    self.assertEqual(result.returncode,status,result.stdout+result.stderr)
                    self.assertEqual(result.account['args'][1:],['ma','list'])
                    self.assertEqual(result.account['uid'],pwd.getpwnam('asterisk').pw_uid)
                    self.assertFalse(result.account['token'])
                    if source.endswith('uninstall_release.sh'):self.assertEqual(result.account['jit'],'0')

    def test_all_native_fwconsole_operation_shapes_preserve_their_exact_arguments(self):
        cases=[
            ('tools/install_release.sh','fwconsole',['--version']),
            ('tools/install_release.sh','fwconsole',['ma','--no-interaction','--ignorecache','download','dashboard']),
            ('tools/install_release.sh','fwconsole',['ma','list']),
            ('tools/install_release.sh','fwconsole',['reload']),
            ('tools/uninstall_release.sh','run_fwconsole',['ma','uninstall','slsmassnotifyserver']),
            ('tools/uninstall_release.sh','run_fwconsole',['ma','disable','slsmassnotifyserver']),
            ('tools/uninstall_release.sh','run_fwconsole',['ma','delete','slsmassnotifyserver']),
            ('tools/uninstall_release.sh','run_fwconsole',['reload']),
        ]
        for source,entry,args in cases:
            with self.subTest(source=source,args=args):
                result=self.fixture(source,entry+' '+shlex.join(args),immediate=37)
                self.assertEqual(result.returncode,37,result.stderr)
                self.assertEqual(result.account['args'][1:],args)
                self.assertEqual(result.account['uid'],pwd.getpwnam('asterisk').pw_uid)
                self.assertFalse(result.account['token'])

    def test_named_root_runtime_account_is_rejected_before_native_php(self):
        for source,operation in [('tools/install_release.sh','fwconsole ma list'),('tools/uninstall_release.sh','run_fwconsole ma list')]:
            with self.subTest(source=source):
                result=self.fixture(source,operation,immediate=0,invalid_uid=True)
                self.assertNotEqual(result.returncode,0,'A named root runtime identity reached native PHP')
                self.assertEqual(result.account,{},'Native PHP executed before root identity refusal')

    def test_primary_gid_zero_is_refused_without_pinning_other_positive_ids(self):
        for source,operation in [('tools/install_release.sh','fwconsole ma list'),('tools/uninstall_release.sh','run_fwconsole ma list')]:
            with self.subTest(source=source):
                result=self.fixture(source,operation,immediate=0,invalid_group='zero')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.account,{})
                alternate=self.fixture(source,operation,immediate=0,invalid_group='foreign')
                self.assertEqual(alternate.returncode,0,alternate.stderr)
                self.assertEqual(alternate.account['uid'],pwd.getpwnam('asterisk').pw_uid)

    def test_pipeline_stdin_reaches_actual_php_without_supervisor_script_fd(self):
        for source,operation in [('tools/install_release.sh','printf bounded-input | php -r "$2"'),('tools/uninstall_release.sh','printf bounded-input | run_bounded_as_asterisk /usr/bin/php -d pcre.jit=0 -r "$2"')]:
            with self.subTest(source=source):
                result=self.fixture(source,operation,stdin=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,'Ym91bmRlZC1pbnB1dA==')

    def test_existing_short_native_budget_is_supervised_without_replacement(self):
        result=self.fixture('tools/install_release.sh','sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=.1 .2 /usr/bin/php -r "$2"')
        self.assertTrue(result.native_connected)
        self.assertIn(result.returncode,(124,137),result.stderr)
        self.assertLess(result.elapsed,1.5)

    def test_freepbx_php_transport_has_the_same_whole_hook_deadline(self):
        for source,operation in [('tools/install_release.sh','php -r "$2"'),('tools/uninstall_release.sh','run_bounded_as_asterisk /usr/bin/php -d pcre.jit=0 -r "$2"')]:
            with self.subTest(source=source):
                result=self.fixture(source,operation)
                self.assertTrue(result.native_connected,'Native PHP hook did not reach the actual CLI')
                self.assertIn(result.returncode,(124,137),result.stdout+result.stderr)
                self.assertLess(result.elapsed,1.5)


class NativePbxOwnedDescendants(unittest.TestCase):
    def run_tree(self, source_name, *, success=False, stubborn=False, kill_parent=False, cancel_at_cleanup=False, kill_supervisor=False, kill_waiter=False, kill_group=False, kill_both=False, actual_uninstall_wrapper=False):
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-pbx-tree-') as name:
            base=Path(name);base.chmod(0o755);data=base/'data';data.mkdir(mode=0o700)
            helper=base/'helper';helper.mkdir(mode=0o700)
            guard=ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_guard.py'
            shutil.copyfile(guard,helper/guard.name)
            marker=base/'child.json';marker.touch(mode=0o666);marker.chmod(0o666)
            program=base/'native.py'
            program.write_text('''import json,os,pathlib,signal,sys,time
if os.fork()==0:
 os.setsid();signal.signal(signal.SIGTERM,signal.SIG_IGN)
 inherited=[]
 for fd in pathlib.Path('/proc/self/fd').iterdir():
  try:target=os.readlink(fd)
  except FileNotFoundError:continue
  if target.startswith(sys.argv[2]+'/') or target.startswith('/run/sls-native-command-') or target==str(pathlib.Path(sys.argv[2]).parent/'maintenance.lock') or fd.name=='3':inherited.append(target)
 pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'inherited':inherited}))
 time.sleep(8);os._exit(0)
if sys.argv[3]=='success':
 time.sleep(.1);sys.exit(0)
if sys.argv[3]=='stubborn':signal.signal(signal.SIGTERM,signal.SIG_IGN)
time.sleep(8)
''');program.chmod(0o644)
            source=(ROOT/source_name).read_text().replace('--kill-after=5 1200','--kill-after=.1 '+('1.2' if kill_supervisor or kill_waiter or kill_group or kill_both else '.3'))
            if cancel_at_cleanup:
                trace=base/'cancel-at-cleanup.py'
                trace.write_text('''import ast,os,signal,sys
from pathlib import Path
body=Path(sys.argv[1]).read_text();tree=ast.parse(body)
node=next(n for n in tree.body if isinstance(n,ast.Try) and n.finalbody)
target=node.finalbody[0].lineno;name='native-cleanup-cancellation-fixture';sent=False
sys.argv=sys.argv[1:]
def inject(frame,event,arg):
 global sent
 if not sent and event=='line' and frame.f_code.co_filename==name and frame.f_lineno==target and frame.f_globals.get('cleanup') is False:
  sent=True;os.kill(os.getpid(),signal.SIGTERM)
 return inject
sys.settrace(inject)
exec(compile(body,name,'exec'),{'__name__':'__main__','__file__':'/dev/fd/3'})
''');trace.chmod(0o644)
                boundary='/usr/bin/python3 -I /dev/fd/3'
                self.assertEqual(source.split('PYSLSBOUNDEDNATIVE\n}',1)[0].count(boundary),1)
                source=source.replace(boundary,'/usr/bin/python3 -I '+shlex.quote(str(trace))+' /dev/fd/3',1)
            entry=base/'entry.sh';entry.write_text(source);entry.chmod(0o644)
            install=source_name=='tools/install_release.sh'
            prefix=('WORKER_GUARD_TOOL="$2/helper/sls_install_guard.py"; ensure_data_directory() { :; }; acquire_worker_coordination; trap release_worker_coordination EXIT; '
                    if install else 'RECOVERY_SIGNER_DIR="$2/helper"; acquire_uninstall_workers; trap release_uninstall_workers EXIT; ')
            invoke=('sls_bounded_as_asterisk' if install else 'run_bounded_as_asterisk')+' /usr/bin/python3 -I "$2/native.py" "$2/child.json" "$2/data" "$3"'
            native_target=None
            if actual_uninstall_wrapper:
                self.assertFalse(install)
                # Retain the actual PHP/run_fwconsole/account/waiter boundary;
                # only its vendor script is an inert private-namespace fixture.
                mode='success' if success else ('stubborn' if stubborn else 'timeout')
                command=shlex.join(['/usr/bin/python3','-I',str(program),str(marker),str(data),mode])
                native=base/'fwconsole.php';native.write_text('<?php passthru('+json.dumps(command)+',$status);exit($status);');native.chmod(0o644)
                native_target=Path('/usr/sbin/fwconsole').resolve(strict=False)
                if not native_target.exists():
                    self.assertEqual(native_target,Path('/var/lib/asterisk/bin/fwconsole'))
                    native_target.parent.mkdir(parents=True,exist_ok=True);native_target.parent.chmod(0o755);native_target.touch(mode=0o755)
                subprocess.run(['mount','--bind',str(native),str(native_target)],check=True,capture_output=True)
                invoke='run_fwconsole reload'
            # The actual command-substitution consumer must complete even when
            # a successful background service inherits its parent's output.
            shell='source "$1"; DATA_DIR="$2/data"; SLS_MASS_NOTIFY_MAINTENANCE_LOCK="$2/maintenance.lock"; exec {maintenance_fd}>"$2/maintenance.lock"; flock -x "$maintenance_fd"; '+prefix+'if value="$('+invoke+')"; then printf "CALLER_FINISHED\\n"; else exit "$?"; fi'
            process=subprocess.Popen(['/bin/bash','-c',shell,'fixture',str(entry),str(base),'success' if success else ('stubborn' if stubborn else 'timeout')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            pidfd=None;lock=None;maintenance=None;started=time.monotonic()
            try:
                until=time.monotonic()+2
                while not marker.stat().st_size and process.poll() is None and time.monotonic()<until:time.sleep(.005)
                self.assertTrue(marker.stat().st_size,'Bounded native account did not reach the owned real child')
                row=json.loads(marker.read_text());pidfd=os.pidfd_open(row['pid'])
                self.assertEqual(row['uid'],pwd.getpwnam('asterisk').pw_uid)
                inherited=row['inherited']
                if actual_uninstall_wrapper:
                    # Real PHP may retain its own public vendor-source FD3.
                    # It is not an immutable root helper/lease capability.
                    inherited=[target for target in inherited if target!=str(native_target)]
                self.assertEqual(inherited,[],'Native descendant received root worker/code descriptors')
                ancestor=row['pid'];scope=None
                while ancestor!=process.pid:
                    raw=Path('/proc/%d/stat'%ancestor).read_text();parent=int(raw.rsplit(')',1)[1].split()[1])
                    args=Path('/proc/%d/cmdline'%ancestor).read_bytes().split(b'\0')
                    if args[:3]==[b'/usr/bin/python3',b'-I',b'/dev/fd/3'] and len(args)>3:
                        candidate=Path(os.fsdecode(args[3]))/'scope.json'
                        if candidate.is_file():scope=json.loads(candidate.read_text());break
                    ancestor=parent
                stage_held={}
                if scope is not None:
                    expected={str(data/'schedule-runner.lock'),str(base/'maintenance.lock')}
                    for stage in ('waiter_pid','supervisor_pid'):
                        held=set()
                        for descriptor in Path('/proc/%d/fd'%scope[stage]).iterdir():
                            try:target=os.readlink(descriptor)
                            except FileNotFoundError:continue
                            if target in expected:held.add(target)
                        stage_held[stage]=held
                        if not actual_uninstall_wrapper:self.assertEqual(held,expected,'An immutable root stage lost its actual worker/maintenance lease copies')
                lock=os.open(data/'schedule-runner.lock',os.O_RDONLY)
                maintenance=os.open(base/'maintenance.lock',os.O_RDONLY)
                with self.assertRaises(BlockingIOError):fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                if kill_supervisor or kill_waiter or kill_group or kill_both:
                    # Pin only this fixture's root inline supervisor through
                    # the known native descendant's actual parent chain.
                    ancestor=row['pid'];supervisor=None
                    while ancestor!=process.pid:
                        raw=Path('/proc/%d/stat'%ancestor).read_text();tail=raw.rsplit(')',1)[1].split();parent=int(tail[1])
                        args=Path('/proc/%d/cmdline'%ancestor).read_bytes().split(b'\0')
                        if args[:3]==[b'/usr/bin/python3',b'-I',b'/dev/fd/3'] and (b'/usr/sbin/fwconsole' if actual_uninstall_wrapper else str(program).encode()) in args:
                            supervisor=ancestor;scope_args=args;break
                        ancestor=parent
                    self.assertIsNotNone(supervisor,'Owned root supervisor was not identified')
                    scope_path=Path(os.fsdecode(scope_args[3]))/'scope.json'
                    if scope_path.is_file():
                        scope=json.loads(scope_path.read_text())
                        supervisor=scope['waiter_pid' if kill_waiter else 'supervisor_pid']
                    if kill_both:
                        descriptors=[os.pidfd_open(scope[key]) for key in ('waiter_pid','supervisor_pid')]
                        try:
                            for descriptor in descriptors:signal.pidfd_send_signal(descriptor,signal.SIGSTOP)
                            for descriptor in reversed(descriptors):signal.pidfd_send_signal(descriptor,signal.SIGKILL)
                        finally:
                            for descriptor in descriptors:os.close(descriptor)
                        time.sleep(.15)
                        self.assertFalse(select.select([pidfd],[],[],0)[0])
                        with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        with self.assertRaises(BlockingIOError):fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        self.assertIsNone(process.poll(),'Unknown completion started rollback')
                        self.assertTrue(scope_path.is_file(),'Interrupted volatile scope evidence was erased')
                        self.assertFalse((scope_path.parent/'completed.json').exists())
                        os.set_blocking(process.stderr.fileno(),False);message=b'';until=time.monotonic()+.5
                        while b'CRITICAL: Native completion is unverified' not in message and time.monotonic()<until:
                            message+=process.stderr.read() or b'';time.sleep(.01)
                        self.assertIn(b'CRITICAL: Native completion is unverified',message)
                        return
                    if actual_uninstall_wrapper:
                        self.assertIsNotNone(scope,'Actual fwconsole wrapper did not create immutable root completion stages')
                        # Freeze only these exact owned immutable stages so
                        # caller-death cleanup cannot erase the live-writer
                        # lease window before the independent kernel probe.
                        stages=[os.pidfd_open(scope[key]) for key in ('waiter_pid','supervisor_pid')]
                        try:
                            for descriptor in stages:signal.pidfd_send_signal(descriptor,signal.SIGSTOP)
                            until=time.monotonic()+.5
                            while time.monotonic()<until:
                                states=[Path('/proc/%d/stat'%scope[key]).read_text().rsplit(')',1)[1].split()[0]for key in ('waiter_pid','supervisor_pid')]
                                if all(state in ('T','t')for state in states):break
                                time.sleep(.005)
                            self.assertTrue(all(state in ('T','t')for state in states),'Owned immutable stages did not stop before fault probe')
                            os.killpg(process.pid,signal.SIGKILL)
                            process.wait(timeout=1)
                            self.assertFalse(select.select([pidfd],[],[],0)[0],'Owned detached native writer retired before the maintenance-fence probe')
                            with self.assertRaises(BlockingIOError,msg='Actual fwconsole wrapper lost maintenance fencing after outer group death while the native writer was live'):
                                fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                            with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        finally:
                            for descriptor in stages:
                                try:signal.pidfd_send_signal(descriptor,signal.SIGCONT)
                                except ProcessLookupError:pass
                                os.close(descriptor)
                    elif kill_group:os.killpg(process.pid,signal.SIGKILL)
                    else:
                        supervisor_fd=os.pidfd_open(supervisor)
                        try:signal.pidfd_send_signal(supervisor_fd,signal.SIGKILL)
                        finally:os.close(supervisor_fd)
                    until=time.monotonic()+2
                    while not select.select([pidfd],[],[],0)[0] and time.monotonic()<until:
                        with self.assertRaises(BlockingIOError,msg='Root stage death released the worker fence while the owned writer was live'):
                            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        with self.assertRaises(BlockingIOError,msg='Root stage death released the maintenance fence while the owned writer was live'):
                            fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        if not kill_group:self.assertIsNone(process.poll(),'Caller began rollback before native retirement was proved')
                        time.sleep(.005)
                    self.assertTrue(select.select([pidfd],[],[],0)[0],'Owned writer did not retire after root-stage loss')
                    if actual_uninstall_wrapper:
                        for stage,held in stage_held.items():self.assertEqual(held,expected,'Actual fwconsole wrapper stripped an immutable root stage maintenance lease')
                    stdout,stderr=process.communicate(timeout=2)
                    if kill_group:self.assertEqual(process.returncode,-signal.SIGKILL)
                    else:self.assertIn(process.returncode,(124,125,137,143),stdout.decode()+stderr.decode())
                    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    fcntl.flock(maintenance,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    return
                if kill_parent:
                    process.kill();process.wait(timeout=1)
                    with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                try:stdout,stderr=process.communicate(timeout=2)
                except subprocess.TimeoutExpired:self.fail('Shell consumer remained blocked by an inherited native output pipe')
                self.assertLess(time.monotonic()-started,1.6)
                child_retired=bool(select.select([pidfd],[],[],0)[0])
                if cancel_at_cleanup:
                    self.assertEqual(process.returncode,143,stderr.decode())
                    self.assertTrue(child_retired,'Cancellation skipped owned-child retirement at cleanup entry')
                elif success:
                    self.assertEqual(process.returncode,0,stderr.decode());self.assertIn(b'CALLER_FINISHED',stdout)
                    self.assertFalse(child_retired,'Successful native service was killed as timeout cleanup')
                else:
                    if kill_parent:self.assertEqual(process.returncode,-signal.SIGKILL)
                    else:
                        # The fixture's .1s grace can also escalate real
                        # runuser's TERM handling; neither timeout is success.
                        self.assertIn(process.returncode,(137,) if stubborn else (124,137),stdout.decode()+stderr.decode())
                    self.assertTrue(child_retired,'A timed-out detached TERM-resistant writer outlived the fenced operation')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                if pidfd is not None:
                    try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    except ProcessLookupError:pass
                    os.close(pidfd)
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                process.communicate(timeout=3)
                if lock is not None:os.close(lock)
                if maintenance is not None:os.close(maintenance)
                if native_target is not None:subprocess.run(['umount',str(native_target)],check=True,capture_output=True)

    def test_timeout_retires_detached_resistant_descendants_before_fence_release(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source)

    def test_kill_escalation_preserves_137_and_retires_the_owned_tree(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,stubborn=True)

    def test_caller_death_cannot_release_fences_while_owned_writer_is_live(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,kill_parent=True)

    def test_supervisor_only_sigkill_cannot_release_fences_or_start_rollback(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,kill_supervisor=True)

    def test_waiter_only_sigkill_awaits_surviving_supervisors_completion(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,kill_waiter=True)

    def test_outer_caller_group_death_preserves_both_fences_until_retirement(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,kill_group=True)

    def test_actual_uninstaller_fwconsole_wrapper_keeps_both_fences_after_caller_group_death(self):
        self.run_tree('tools/uninstall_release.sh',kill_group=True,actual_uninstall_wrapper=True)

    def test_missing_completion_remains_contained_with_volatile_evidence_retained(self):
        # Both independent stages are deliberately lost here; only the live
        # Bash holder is relied upon. This does not certify loss of all holders.
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,kill_both=True)

    def test_signal_at_success_cleanup_entry_cannot_bypass_retirement(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,success=True,cancel_at_cleanup=True)

    def test_success_keeps_native_service_and_completes_the_shell_capture(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source):self.run_tree(source,success=True)


class NativePbxOuterBoundary(unittest.TestCase):
    def entry(self,base,source_name):
        source=(ROOT/source_name).read_text().replace('--kill-after=5 1200','--kill-after=.1 .2')
        source=source.replace('--kill-after=2 20','--kill-after=.1 .2').replace('--kill-after=2 10','--kill-after=.1 .2')
        entry=base/'entry.sh';entry.write_text(source);entry.chmod(0o644)
        invoke='sls_bounded_as_asterisk' if source_name.endswith('/install_release.sh') else 'run_bounded_as_asterisk'
        return entry,invoke

    def test_account_transition_is_inside_the_whole_command_deadline(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            for operation,stubborn in [('default',False),('default',True),('asterisk',False),('plain',False)]+([('soxi',False),('identify',False)] if source.endswith('/install_release.sh') else []):
                with self.subTest(source=source,operation=operation,stubborn=stubborn),tempfile.TemporaryDirectory(dir='/run',prefix='sls-prefix-') as name:
                    base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                    if operation=='plain':invoke='sls_as_asterisk' if source.endswith('/install_release.sh') else 'run_as_asterisk'
                    elif operation!='default':invoke=operation
                    prefix=base/'prefix.py'
                    prefix.write_text('#!/usr/bin/python3\nimport signal,time\n'+('signal.signal(signal.SIGTERM,signal.SIG_IGN)\n' if stubborn else '')+'time.sleep(2)\n')
                    prefix.chmod(0o755);target=Path('/usr/sbin/runuser').resolve()
                    subprocess.run(['mount','--bind',str(prefix),str(target)],check=True,capture_output=True)
                    try:
                        before=time.monotonic()
                        result=subprocess.run(['/bin/bash','-c','source "$1"; '+invoke+' /usr/bin/true','fixture',str(entry)],capture_output=True,text=True,timeout=3)
                        elapsed=time.monotonic()-before
                        self.assertEqual(result.returncode,137 if stubborn else 124,result.stdout+result.stderr)
                        self.assertLess(elapsed,1.2,'Native account transition escaped the operation clock')
                    finally:subprocess.run(['umount',str(target)],check=True,capture_output=True)

    def test_cooperative_term_output_is_drained_during_the_fixed_kill_grace(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-term-output-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                identity=pwd.getpwnam('asterisk');os.chown(base,identity.pw_uid,identity.pw_gid)
                payload=base/'term.py';marker=base/'finished'
                payload.write_text('import os,pathlib,signal,sys,time\ndef finish(n,f):\n os.write(2,b"x"*1048576)\n pathlib.Path(sys.argv[1]).write_text("finished")\n sys.exit(0)\nsignal.signal(signal.SIGTERM,finish)\ntime.sleep(3)\n');payload.chmod(0o644)
                waiter='run_without_install_maintenance_lock' if source.endswith('/install_release.sh') else 'run_without_uninstall_worker_descriptors'
                result=subprocess.run(['/bin/bash','-c','source "$1"; '+waiter+' sls_bounded_native_command .15 .4 /usr/bin/python3 -I "$2" "$3"','fixture',str(entry),str(payload),str(marker)],capture_output=True,timeout=2)
                self.assertEqual(result.returncode,124,result.stderr[-200:].decode())
                self.assertTrue(marker.exists(),'A finite cooperative TERM handler was starved of its output pipe')
                self.assertEqual(result.stderr,b'x'*1048576)

    def test_regular_log_output_keeps_the_callers_shared_file_offset(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-regular-output-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                log=base/'output.log'
                result=subprocess.run(['/bin/bash','-c','source "$1"; exec 4>"$2"; printf before >&4; '+invoke+' /usr/bin/printf middle >&4; printf after >&4','fixture',str(entry),str(log)],capture_output=True,timeout=2)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                self.assertEqual(log.read_bytes(),b'beforemiddleafter')

    def test_non_draining_socket_output_is_also_bounded(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-socket-output-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                reader,writer=socket.socketpair();writer.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
                payload=base/'output.py';payload.write_text('import os,time\nos.write(1,b"x"*1048576)\ntime.sleep(3)\n');payload.chmod(0o644)
                process=subprocess.Popen(['/bin/bash','-c','source "$1"; '+invoke+' /usr/bin/python3 -I "$2"','fixture',str(entry),str(payload)],stdout=writer,stderr=subprocess.PIPE)
                writer.close()
                try:
                    process.wait(timeout=1.2)
                    self.assertIn(process.returncode,(124,137),process.stderr.read().decode())
                finally:
                    reader.close()
                    if process.poll() is None:process.kill()
                    process.communicate(timeout=3)

    def test_supervision_error_after_foreground_success_cannot_report_success(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-final-output-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                adapter=base/'adapter.py';adapter.write_text('import fcntl,sys\nfrom pathlib import Path\nbody=Path(sys.argv[1]).read_text();sys.argv=sys.argv[1:]\noriginal=fcntl.fcntl\ndef failed(fd,operation,*args):\n if operation==fcntl.F_GETPIPE_SZ:raise OSError("private final-drain failure")\n return original(fd,operation,*args)\nfcntl.fcntl=failed\nexec(compile(body,"native-final-output-fixture","exec"),{"__name__":"__main__"})\n')
                text=entry.read_text();boundary='/usr/bin/python3 -I /dev/fd/3';text=text.replace(boundary,'/usr/bin/python3 -I '+shlex.quote(str(adapter))+' /dev/fd/3',1);entry.write_text(text)
                result=subprocess.run(['/bin/bash','-c','source "$1"; '+invoke+' /usr/bin/true','fixture',str(entry)],capture_output=True,timeout=2)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'Native PBX command supervision failed',result.stderr)

    def test_root_public_key_cleanup_cannot_wait_indefinitely(self):
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-root-gpg-') as name:
            base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,'tools/uninstall_release.sh')
            home=base/'gnupg';home.mkdir();probe=base/'gpg.py'
            probe.write_text('import time\ntime.sleep(2)\n');probe.chmod(0o644)
            source=entry.read_text().replace('for home in /root/.gnupg /home/asterisk/.gnupg /var/lib/asterisk/.gnupg; do','for home in '+shlex.quote(str(home))+'; do',1)
            source=source.replace('if [ "$home" = "/root/.gnupg" ]; then','if [ "$home" = '+shlex.quote(str(home))+' ]; then',1)
            source=source.replace('/usr/bin/gpg','/usr/bin/python3 -I '+shlex.quote(str(probe)))
            entry.write_text(source)
            before=time.monotonic()
            result=subprocess.run(['/bin/bash','-c','source "$1"; SIGN_HOME="$2/private-no-key"; SIGNING_FINGERPRINT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; remove_trusted_signing_key','fixture',str(entry),str(base)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertLess(time.monotonic()-before,1.2,'Root GPG cleanup escaped the fixed native-operation budget')

    def test_pre_admission_syscall_refusal_returns_without_an_unknown_work_hold(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-refused-scope-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                adapter=base/'refuse.py';adapter.write_text('import os,sys\nfrom pathlib import Path\nbody=Path(sys.argv[1]).read_text();sys.argv=sys.argv[1:]\ndef denied():raise PermissionError(1,"private fixture denied setsid")\nos.setsid=denied\nexec(compile(body,"native-admission-refusal-fixture","exec"),{"__name__":"__main__"})\n')
                text=entry.read_text();text=text.replace('/usr/bin/python3 -I /dev/fd/3','/usr/bin/python3 -I '+shlex.quote(str(adapter))+' /dev/fd/3',1);entry.write_text(text)
                before=set(Path('/run').glob('sls-native-command-*'))
                process=subprocess.Popen(['/bin/bash','-c','source "$1"; '+invoke+' /usr/bin/touch "$2"','fixture',str(entry),str(base/'native-must-not-run')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                completed=True
                try:
                    try:stdout,stderr=process.communicate(timeout=1.2)
                    except subprocess.TimeoutExpired:completed=False;stdout=stderr=b''
                    self.assertTrue(completed,'A refusal before any mutable admission became a permanent unknown-work hold')
                    self.assertEqual(process.returncode,1,stderr.decode())
                    self.assertFalse((base/'native-must-not-run').exists())
                    self.assertEqual(set(Path('/run').glob('sls-native-command-*')),before)
                finally:
                    if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
                    process.communicate(timeout=3)
                    for directory in set(Path('/run').glob('sls-native-command-*'))-before:
                        for child in directory.iterdir():child.unlink()
                        directory.rmdir()

    def test_emergency_root_diagnostic_preserves_existing_regular_log_bytes(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-emergency-log-') as name:
                base=Path(name);body=(ROOT/source).read_text().split("3<<'PYSLSBOUNDEDNATIVE'\n",1)[1].split('PYSLSBOUNDEDNATIVE\n}',1)[0]
                tree=ast.parse(body);functions=[ast.get_source_segment(body,node) for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('diagnostic','contain_scope')]
                self.assertTrue(functions)
                probe=base/'diagnostic.py';probe.write_text('import os,signal,socket,stat,time\ncancel_signals=(signal.SIGTERM,signal.SIGINT,signal.SIGHUP)\ncompletion_name="/run/private-synthetic-evidence"\n'+'\n\n'.join(functions)+'\ndef finished(*args):raise SystemExit(0)\ntime.sleep=finished\ncontain_scope()\n')
                log=base/'retained.log';log.write_bytes(b'prior installer evidence\n')
                with log.open('ab') as error:
                    result=subprocess.run(['/usr/bin/python3','-I',str(probe)],stderr=error,capture_output=False,timeout=2)
                self.assertEqual(result.returncode,0)
                self.assertTrue(log.read_bytes().startswith(b'prior installer evidence\n'),'Emergency supervision diagnostic overwrote earlier installer evidence')
                self.assertIn(b'CRITICAL:',log.read_bytes())

    def test_non_draining_output_sink_does_not_disable_the_whole_command_clock(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            with self.subTest(source=source),tempfile.TemporaryDirectory(dir='/run',prefix='sls-output-') as name:
                base=Path(name);base.chmod(0o755);entry,invoke=self.entry(base,source)
                payload=base/'output.py';payload.write_text('import os,time\nos.write(1,b"x"*1048576)\ntime.sleep(3)\n');payload.chmod(0o644)
                process=subprocess.Popen(['/bin/bash','-c','source "$1"; '+invoke+' /usr/bin/python3 -I "$2"','fixture',str(entry),str(payload)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                completed=True
                try:
                    try:process.wait(timeout=1.2)
                    except subprocess.TimeoutExpired:completed=False
                    # Drain only after the observation. This also safely lets
                    # the old supervisor finish without an unrelated signal.
                    stdout,stderr=process.communicate(timeout=4)
                    self.assertTrue(completed,'Blocked downstream output disabled the root operation clock')
                    self.assertIn(process.returncode,(124,137),stderr.decode())
                finally:
                    if process.poll() is None:process.kill()
                    process.communicate(timeout=4)


class NativeCompletionRecordValidation(unittest.TestCase):
    def invoke(self,source,*arguments,user=None):
        command=['/bin/bash','-c','source "$1"; shift; sls_native_completion_record "$@"','fixture',str(ROOT/source),*arguments]
        if user:command=['/usr/sbin/runuser','-u',user,'--',*command]
        return subprocess.run(command,capture_output=True,text=True,timeout=2)

    def test_protected_completion_validation_refuses_forged_or_unsafe_records(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            prepared=self.invoke(source,'prepare')
            self.assertEqual(prepared.returncode,0,prepared.stderr)
            directory,nonce=prepared.stdout.splitlines();directory=Path(directory);record=directory/'completed.json'
            scope={'schema':1,'magic':'sls-native-scope-v1','nonce':nonce,'forked':True,'waiter_pid':os.getppid(),'waiter_start':1,'supervisor_pid':os.getpid(),'supervisor_start':1}
            (directory/'scope.json').write_text(json.dumps(scope)+'\n');(directory/'scope.json').chmod(0o600)
            valid={'schema':1,'magic':'sls-native-completion-v1','nonce':nonce,'status':37,'pid':os.getpid()}
            try:
                for alteration in ('valid','nonce','magic','status','world-readable','foreign-owner','hardlink','symlink'):
                    with self.subTest(source=source,alteration=alteration):
                        item=dict(valid)
                        if alteration in ('nonce','magic'):item[alteration]='wrong'
                        if alteration=='status':item['status']=0
                        record.write_text(json.dumps(item)+'\n');record.chmod(0o600)
                        if alteration=='world-readable':record.chmod(0o644)
                        if alteration=='foreign-owner':os.chown(record,pwd.getpwnam('asterisk').pw_uid,pwd.getpwnam('asterisk').pw_gid)
                        extra=directory/'extra'
                        if alteration=='hardlink':os.link(record,extra)
                        if alteration=='symlink':record.rename(extra);record.symlink_to('extra')
                        result=self.invoke(source,'verify',str(directory),nonce,'37')
                        self.assertEqual(result.returncode==0,alteration=='valid',result.stderr)
                        record.unlink()
                        if extra.exists():extra.unlink()
                directory.chmod(0o755)
                self.assertNotEqual(self.invoke(source,'verify',str(directory),nonce,'37').returncode,0)
            finally:
                for item in directory.iterdir():item.unlink()
                directory.rmdir()

    def test_native_account_cannot_publish_into_the_root_completion_directory(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            prepared=self.invoke(source,'prepare');self.assertEqual(prepared.returncode,0,prepared.stderr)
            directory,nonce=prepared.stdout.splitlines();directory=Path(directory)
            try:
                result=subprocess.run(['/usr/sbin/runuser','-u','asterisk','--','/usr/bin/python3','-I','-c','from pathlib import Path;import sys;Path(sys.argv[1]).write_text("forged")',str(directory/'completed.json')],capture_output=True,text=True,timeout=2)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('PermissionError',result.stderr)
                self.assertFalse((directory/'completed.json').exists())
                self.assertEqual(directory.stat().st_mode&0o777,0o700)
            finally:directory.rmdir()

    def test_pre_admission_completion_can_only_certify_failure(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            prepared=self.invoke(source,'prepare');self.assertEqual(prepared.returncode,0,prepared.stderr)
            directory,nonce=prepared.stdout.splitlines();directory=Path(directory)
            try:
                scope={'schema':1,'magic':'sls-native-scope-v1','nonce':nonce,'forked':False,'waiter_pid':os.getpid(),'waiter_start':1,'supervisor_pid':0,'supervisor_start':0}
                (directory/'scope.json').write_text(json.dumps(scope));(directory/'scope.json').chmod(0o600)
                for status in (1,0):
                    record=directory/'completed.json';record.write_text(json.dumps({'schema':1,'magic':'sls-native-completion-v1','nonce':nonce,'status':status,'pid':os.getpid()}));record.chmod(0o600)
                    result=self.invoke(source,'verify',str(directory),nonce,str(status))
                    self.assertEqual(result.returncode==0,status!=0)
            finally:
                for item in directory.iterdir():item.unlink()
                directory.rmdir()

    def test_repeated_cancellation_does_not_replace_a_record_under_an_active_reader(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            prepared=self.invoke(source,'prepare');self.assertEqual(prepared.returncode,0,prepared.stderr)
            directory,nonce=prepared.stdout.splitlines();directory=Path(directory)
            try:
                first=self.invoke(source,'cancel',str(directory),nonce,'15');self.assertEqual(first.returncode,0,first.stderr)
                before=(directory/'cancel.json').read_bytes()
                test=self;original_read=os.read;injected=False
                class ControlledOS:
                    def __getattr__(self,name):return getattr(os,name)
                    def read(self,descriptor,size):
                        nonlocal injected
                        body=original_read(descriptor,size)
                        if not injected and os.readlink('/proc/self/fd/%d'%descriptor).endswith('/cancel.json'):
                            injected=True
                            second=test.invoke(source,'cancel',str(directory),nonce,'1')
                            test.assertEqual(second.returncode,0,second.stderr)
                        return body
                body=(ROOT/source).read_text().split("3<<'PYSLSBOUNDEDNATIVE'\n",1)[1].split('PYSLSBOUNDEDNATIVE\n}',1)[0]
                tree=ast.parse(body);functions=ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('identity','read_record','cancellation_record')],type_ignores=[])
                namespace={'os':ControlledOS(),'json':json,'stat':__import__('stat'),'cancel_signals':(signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
                exec(compile(functions,'actual-cancellation-reader-fixture','exec'),namespace)
                descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    try:result=namespace['cancellation_record'](descriptor,nonce)
                    except ValueError as error:self.fail('A legitimate second cancellation invalidated the active protected reader: '+str(error))
                finally:os.close(descriptor)
                self.assertTrue(injected)
                self.assertEqual(result,15,'The first accepted cancellation should govern both root stages')
                self.assertEqual((directory/'cancel.json').read_bytes(),before)
            finally:
                for item in directory.iterdir():item.unlink()
                directory.rmdir()

    def test_cancel_retry_preserves_and_refuses_an_unknown_retained_binding(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            prepared=self.invoke(source,'prepare');self.assertEqual(prepared.returncode,0,prepared.stderr)
            directory,nonce=prepared.stdout.splitlines();directory=Path(directory)
            try:
                record=directory/'cancel.json';record.write_text(json.dumps({'schema':1,'magic':'sls-native-cancel-v1','nonce':'0'*64,'signal':15}));record.chmod(0o600)
                before=record.read_bytes()
                result=self.invoke(source,'cancel',str(directory),nonce,'1')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(record.read_bytes(),before,'A new request overwrote unrecognized protected cancellation evidence')
            finally:
                for item in directory.iterdir():item.unlink()
                directory.rmdir()

    def test_nonroot_cannot_create_or_validate_root_completion_capabilities(self):
        for source in ('tools/install_release.sh','tools/uninstall_release.sh'):
            result=self.invoke(source,'prepare',user='asterisk')
            self.assertNotEqual(result.returncode,0)


class ManualWeatherPickupDeadline(unittest.TestCase):
    def pickup(self,stall,timeout_seconds="1"):
        source=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify_test.sh').read_text()
        function=source.split('wait_for_test_call_pickup() {',1)[1].split('\nload_central_config() {',1)[0]
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-weather-pickup-') as name:
            base=Path(name);base.chmod(0o755);identity=pwd.getpwnam('asterisk');os.chown(base,identity.pw_uid,identity.pw_gid)
            queue=base/'owned.call';queue.touch();queue.chmod(0o666)
            endpoint=base/'control.sock';server=socket.socket(socket.AF_UNIX);server.bind(str(endpoint));endpoint.chmod(0o666);server.listen(1);server.settimeout(4)
            reached=threading.Event();release=threading.Event()
            def serve():
                try:
                    connection,_=server.accept()
                    with connection:
                        reached.set()
                        if stall:release.wait(4.2)
                        else:queue.unlink()
                except OSError:pass
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            cli=base/'native-cli';cli.write_text('#!/bin/bash\nexec /usr/sbin/asterisk -s '+shlex.quote(str(endpoint))+' "$@"\n');cli.chmod(0o755)
            entry=base/'pickup.sh'
            entry.write_text('wait_for_test_call_pickup() {'+function+'\nLOG='+shlex.quote(str(base/'log'))+'\nASTERISK_CLI_BIN='+shlex.quote(str(cli))+'\nTEST_SPOOL_PICKUP_TIMEOUT_SECONDS='+shlex.quote(timeout_seconds)+'\nSLS_AUDIO_CONTEXT=sls-owned-fixture\ndeclare -a TEST_CALL_QUEUE_PATHS=('+shlex.quote(str(queue))+')\ndeclare -A TEST_CALL_ACCEPTED TEST_CALL_RECIPIENTS\nTEST_CALL_RECIPIENTS['+shlex.quote(str(queue))+']=1234\nwait_for_test_call_pickup\n');entry.chmod(0o644)
            before=time.monotonic()
            try:
                result=subprocess.run(['/usr/sbin/runuser','-u','asterisk','--','/bin/bash',str(entry)],capture_output=True,text=True,timeout=6)
                elapsed=time.monotonic()-before
                self.assertTrue(reached.is_set(),'Manual pickup did not reach the actual native CLI: '+result.stderr)
                self.assertEqual(result.returncode,1 if stall else 0,result.stdout+result.stderr)
                self.assertLess(elapsed,3.6 if stall else 1.8,'Manual pickup CLI escaped its remaining budget plus the fixed 2s KILL grace')
                self.assertFalse(queue.exists(),'Only the owned unaccepted synthetic queue file should be removed')
                if stall:self.assertIn('did not pick up',(base/'log').read_text())
            finally:release.set();server.close();thread.join(timeout=3)

    def test_stalled_native_cli_respects_remaining_manual_pickup_budget(self):self.pickup(True)
    def test_native_queue_pickup_still_completes_successfully(self):self.pickup(False)
    def test_valid_decimal_budget_with_leading_zeroes_is_not_octal(self):self.pickup(False,"08")

if __name__ == '__main__':
    unittest.main()
