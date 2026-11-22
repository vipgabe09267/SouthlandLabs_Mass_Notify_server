#!/usr/bin/python3
"""Real native children stay fenced across independent coordinator death.

This runs the actual shell/guard and runuser boundary inside the disposable
namespace. The native child only publishes inert private fixture files.
"""
import fcntl
import ctypes
import struct
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import tempfile
import time
import unittest
import select
import sys

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_guard.py'
SHELL = r'''
source "$1"
DATA_DIR="$2/data"; SETTINGS_LOCK="$DATA_DIR/mass-notifications.config.lock"
CONFIG_FILE="$DATA_DIR/mass-notifications.config"
WORKER_GUARD_TOOL="$3"
ensure_data_directory() { :; }
trap release_worker_coordination EXIT
acquire_worker_coordination
acquire_settings_coordination
printf '%s\n' "$WORKER_LOCK_PID" >"$2/keeper.pid"
sls_as_asterisk /usr/bin/python3 -I "$2/native.py" "$2/native" &
native_waiter=$!
printf '%s\n' "$native_waiter" >"$2/waiter.pid"
wait "$native_waiter"
while [ ! -f "$2/release-main" ]; do sleep .01; done
'''
NATIVE = r'''
import json,os,pathlib,time
root=pathlib.Path(__import__('sys').argv[1])
inherited=[]
for path in pathlib.Path('/proc/self/fd').iterdir():
    try:target=os.readlink(path)
    except FileNotFoundError:continue
    if target.endswith('.lock') or target.endswith('/audio-reservations.json'):
        inherited.append(target)
(root/'ready.pending').write_text(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'inherited':inherited}))
os.replace(root/'ready.pending',root/'ready')
while not (root/'release').exists():time.sleep(.01)
(root/'finished').write_text('native write finished before lease release')
'''


class ExternalWriterFencingFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/run')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o755)
        account = pwd.getpwnam('asterisk'); self.uid, self.gid = account.pw_uid, account.pw_gid
        for name in ('data', 'native'):
            path = self.root / name; path.mkdir(mode=0o750); os.chown(path,self.uid,self.gid)
        active=self.root/'data/mass-notifications.config'
        active.write_bytes(b'established fixture configuration');active.chmod(0o640)
        os.chown(active,self.uid,self.gid)
        (self.root/'native.py').write_text(NATIVE); (self.root/'native.py').chmod(0o644)
        self.main = subprocess.Popen(['bash','-c',SHELL,'fixture',str(ROOT/'tools/install_release.sh'),
            str(self.root),str(GUARD)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.addCleanup(self.stop)
        ready = self.root/'native/ready'
        self.until(lambda:ready.exists() or self.main.poll() is not None,'native child never reached real runtime boundary')
        if not ready.exists():
            _, stderr = self.main.communicate(timeout=5)
            self.fail('Fixture exited before its native writer started (exit %s): %s' %
                      (self.main.returncode,stderr[-2048:].decode('utf-8','replace')))
        self.keeper = int((self.root/'keeper.pid').read_text())
        self.guard_pid = self.actual_guard_pid(self.keeper)
        self.guard_pidfd = os.pidfd_open(self.guard_pid)
        self.addCleanup(os.close,self.guard_pidfd)
        self.native = json.loads((self.root/'native/ready').read_text())
        self.assertEqual(self.native['uid'],self.uid)
        self.assertEqual(self.native['inherited'],[], 'mutable native child inherited an unlock-capable lease')
        # Pin the complete known native prefix below its root lease holder.
        # The fixture has one writer; detached hooks have separate controls.
        self.native_chain=[];pid=self.native['pid'];self.scope=None
        for _ in range(32):
            args=Path('/proc/%d/cmdline'%pid).read_bytes().split(b'\0')
            if args[:3]==[b'/usr/bin/python3',b'-I',b'/dev/fd/3']:
                self.scope_directory=Path(os.fsdecode(args[3]))
                self.scope=json.loads((self.scope_directory/'scope.json').read_text())
                self.assertEqual(pid,self.scope['supervisor_pid'])
                break
            held=False
            for item in Path('/proc/%d/fd'%pid).iterdir():
                try:target=os.readlink(item)
                except FileNotFoundError:continue
                if target==str(self.root/'data/enterprise-worker.lock'):held=True;break
            if held:break
            descriptor=os.pidfd_open(pid);self.native_chain.append(descriptor);self.addCleanup(os.close,descriptor)
            pid=self.parent_pid(pid)
        self.assertTrue(self.native_chain,'No actual native process was pinned')
        self.original_waiter=int((self.root/'waiter.pid').read_text()) if (self.root/'waiter.pid').exists() else None
        self.bash_waiter=self.parent_pid(self.parent_pid(self.scope['waiter_pid'])) if self.scope else None

    def stop(self):
        try:os.killpg(self.main.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        self.main.communicate(timeout=5)

    def actual_guard_pid(self, parent):
        pending=[parent];observed=[]
        while pending and len(observed)<32:
            pid=pending.pop();observed.append(pid)
            try:
                arguments=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
                children=Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()
            except FileNotFoundError:continue
            if str(GUARD).encode() in arguments and b'hold' in arguments and b'--data' in arguments:
                return pid
            pending.extend(map(int,children))
        self.fail('actual Python guard not found below recorded coprocess: '+repr(observed))

    def kill_actual_guard(self):
        try:
            signal.pidfd_send_signal(self.guard_pidfd,signal.SIGKILL)
        except ProcessLookupError:
            # Coordinator EOF can retire the already-pinned guard first.
            # An unrelated/recycled numeric PID is never signal authority.
            self.assertIsNotNone(self.main.poll(),
                                 'guard exited unexpectedly while its coordinator was live')
        self.assertTrue(select.select([self.guard_pidfd],[],[],2)[0],
                        'the pinned Python lease owner did not retire')

    def until(self, predicate, message, seconds=5):
        deadline=time.monotonic()+seconds
        while not predicate() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(predicate(),message)

    def lock_is_held(self, name):
        descriptor=os.open(self.root/'data'/name,os.O_RDONLY)
        try:
            try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return True
            return False
        finally:os.close(descriptor)

    def assert_fenced(self):
        for name in ('enterprise-worker.lock','announcement-activity.lock','mass-notifications.config.lock'):
            self.assertTrue(self.lock_is_held(name),'native writer lost its actual fence: '+name)

    def finish_native(self):
        (self.root/'native/release').touch()
        self.until(lambda:(self.root/'native/finished').exists(),'actual native writer did not finish')

    def test_keeper_death_keeps_main_and_active_native_writer_fenced(self):
        self.assert_fenced()
        self.kill_actual_guard()
        time.sleep(.1)
        self.assert_fenced()
        self.finish_native()
        self.assert_fenced()  # Main has not explicitly released its retained lease.
        (self.root/'release-main').touch()
        stdout,stderr=self.main.communicate(timeout=5)
        self.assertEqual(self.main.returncode,0,stdout+stderr)
        self.assertFalse(self.lock_is_held('announcement-activity.lock'))
        self.assertFalse(self.lock_is_held('mass-notifications.config.lock'))

    def test_main_and_keeper_death_leave_root_waiter_fence_until_native_exit(self):
        self.assert_fenced()
        self.main.kill(); self.main.wait(timeout=3)
        time.sleep(.1)
        self.assert_fenced()  # Independent main-only death first.
        try:self.kill_actual_guard()
        except ProcessLookupError:pass
        time.sleep(.1)
        self.assert_fenced()  # The actual native waiter's retained descriptions remain.
        self.finish_native()
        self.until(lambda:not self.lock_is_held('announcement-activity.lock'),
                   'completed native writer left a leaked worker lease')
        self.assertFalse(self.lock_is_held('mass-notifications.config.lock'))

    @staticmethod
    def parent_pid(pid):
        raw=Path('/proc/%d/stat'%pid).read_bytes()
        return int(raw.rsplit(b')',1)[1].split()[1])

    def native_retired(self):
        return all(select.select([descriptor],[],[],0)[0] for descriptor in self.native_chain)

    def assert_live_native_fenced(self):
        try:self.assert_fenced()
        except AssertionError:
            # Retirement may race the lock observation. A free fence is valid
            # only after every pinned process in the known native prefix died.
            if not self.native_retired():raise

    def assert_legacy_interrupted_root_waiter(self, interruption):
        pid=self.native['pid'];waiter=None
        for _ in range(16):
            pid=self.parent_pid(pid)
            if pid<=1:break
            for descriptor in Path('/proc/%d/fd'%pid).iterdir():
                try:target=os.readlink(descriptor)
                except FileNotFoundError:continue
                if target==str(self.root/'data/enterprise-worker.lock'):waiter=pid;break
            if waiter is not None:break
        self.assertIsNotNone(waiter,'Native child has no original root waiter retaining its actual fence')
        descriptor=os.pidfd_open(waiter);self.addCleanup(os.close,descriptor)
        self.main.kill();self.main.wait(timeout=3);self.kill_actual_guard()
        signal.pidfd_send_signal(descriptor,interruption);time.sleep(.1)
        self.assert_fenced()
        self.finish_native()
        self.until(lambda:not self.lock_is_held('announcement-activity.lock'),
                   'Interrupted original root waiter failed to reap and release after native exit')

    def assert_interrupted_root_waiter(self, interruption, role='supervisor'):
        if self.scope is None:return self.assert_legacy_interrupted_root_waiter(interruption)
        targets={'supervisor':self.scope['supervisor_pid'],
                 'bash_waiter':self.bash_waiter,'original_waiter':self.original_waiter}
        waiter=targets[role]
        executable=Path('/proc/%d/exe'%waiter).resolve().name
        self.assertTrue(executable.startswith('python3') if role=='supervisor' else executable=='bash',
                        'The fixture selected the wrong immutable root role')
        self.assertEqual(Path('/proc/%d'%waiter).stat().st_uid,0)
        descriptor=os.pidfd_open(waiter);self.addCleanup(os.close,descriptor)
        watch=None
        if role=='bash_waiter' and interruption in (signal.SIGTERM,signal.SIGHUP):
            library=ctypes.CDLL(None,use_errno=True)
            library.inotify_add_watch.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32)
            watch=library.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            self.assertGreaterEqual(watch,0);self.addCleanup(os.close,watch)
            self.assertGreaterEqual(library.inotify_add_watch(watch,os.fsencode(self.scope_directory),0x80),0)
        self.main.kill();self.main.wait(timeout=3);self.kill_actual_guard()
        signal.pidfd_send_signal(descriptor,interruption)
        until=time.monotonic()+.1
        while time.monotonic()<until and not self.native_retired():
            self.assert_live_native_fenced();time.sleep(.005)
        if not self.native_retired():
            self.assert_live_native_fenced()
            (self.root/'native/release').touch()
        self.until(self.native_retired,'Interrupted root role left native prefix processes alive')
        self.until(lambda:not self.lock_is_held('announcement-activity.lock'),
                   'Interrupted root role failed to release after proved native retirement')
        self.assertFalse(self.lock_is_held('enterprise-worker.lock'))
        self.assertFalse(self.lock_is_held('mass-notifications.config.lock'))
        finished=self.root/'native/finished'
        def receipt():
            if not finished.exists():return None
            info=finished.stat();return (info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,finished.read_bytes())
        before=receipt();time.sleep(.05)
        self.assertEqual(receipt(),before,'A private native write occurred after the fence was released')
        if watch is not None:
            events=os.read(watch,65536);names=[]
            while events:
                unused,mask,cookie,length=struct.unpack('iIII',events[:16])
                names.append(events[16:16+length].rstrip(b'\0'));events=events[16+length:]
            self.assertIn(b'cancel.json',names,'The explicitly selected fixed Bash waiter did not publish its protected cancellation')


    def test_term_interrupted_root_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGTERM)

    def test_int_interrupted_root_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGINT)

    def test_hup_interrupted_root_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGHUP)


class ExternalWriterFencing(ExternalWriterFencingFixture,unittest.TestCase):
    def test_term_original_account_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGTERM,'original_waiter')

    def test_int_original_account_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGINT,'original_waiter')

    def test_hup_original_account_waiter_keeps_fence_until_native_exit(self):
        self.assert_interrupted_root_waiter(signal.SIGHUP,'original_waiter')

    def test_term_fixed_bash_waiter_retires_native_before_release(self):
        self.assert_interrupted_root_waiter(signal.SIGTERM,'bash_waiter')

    def test_int_fixed_bash_waiter_retires_native_before_release(self):
        self.assert_interrupted_root_waiter(signal.SIGINT,'bash_waiter')

    def test_hup_fixed_bash_waiter_retires_native_before_release(self):
        self.assert_interrupted_root_waiter(signal.SIGHUP,'bash_waiter')


class RetainedDescriptorAdmission(unittest.TestCase):
    def test_real_runtime_boundary_preserves_native_stdin_and_exit_status(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            data=Path(name)
            script=r'''
source "$1"
DATA_DIR="$2";WORKER_GUARD_TOOL="$3"
ensure_data_directory() { :; }
trap release_worker_coordination EXIT
acquire_worker_coordination
sls_as_asterisk /usr/bin/python3 -I -c 'import sys; body=sys.stdin.buffer.read();sys.stdout.buffer.write(body);raise SystemExit(23)'
'''
            result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),
                str(data),str(GUARD)],input=b'actual private native stdin\n',capture_output=True,timeout=8)
            self.assertEqual(result.returncode,23,result.stdout+result.stderr)
            self.assertEqual(result.stdout,b'actual private native stdin\n')

    def test_swapped_or_replaced_anchors_never_become_guard_authority(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            data=Path(name)
            prepare=subprocess.Popen([sys.executable,'-I',str(GUARD),'--data',str(data),'prepare'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            descriptors=[]
            try:
                self.assertTrue(select.select([prepare.stdout],[],[],5)[0])
                response=prepare.stdout.readline()
                self.assertTrue(response.startswith(b'prepared '),response)
                mapping=json.loads(response.removeprefix(b'prepared '))
                self.assertEqual(mapping['pid'],prepare.pid)
                for descriptor in mapping['fds']:
                    descriptors.append(os.open('/proc/'+str(prepare.pid)+'/fd/'+str(descriptor),os.O_RDONLY))
                prepare.stdin.write(b'release\n');prepare.stdin.flush();prepare.communicate(timeout=5)
                self.assertEqual(prepare.returncode,0)
                swapped=list(descriptors);swapped[0],swapped[1]=swapped[1],swapped[0]
                for values in (swapped,descriptors[:-1],descriptors+[descriptors[0]]):
                    result=subprocess.run([sys.executable,'-I',str(GUARD),'--data',str(data),
                        '--inherited-fds',','.join(map(str,values)),'hold'],input=b'release\n',
                        pass_fds=descriptors,capture_output=True,timeout=5)
                    self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertNotIn(b'ready\n',result.stdout)
                lock=data/'announcement-activity.lock';lock.rename(data/'old-activity.lock')
                lock.write_bytes(b'');lock.chmod(0o640)
                result=subprocess.run([sys.executable,'-I',str(GUARD),'--data',str(data),
                    '--inherited-fds',','.join(map(str,descriptors)),'hold'],input=b'release\n',
                    pass_fds=descriptors,capture_output=True,timeout=5)
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertNotIn(b'ready\n',result.stdout)
            finally:
                if prepare.poll() is None:prepare.kill()
                prepare.communicate(timeout=5)
                for descriptor in descriptors:os.close(descriptor)


if __name__ == '__main__':unittest.main()
