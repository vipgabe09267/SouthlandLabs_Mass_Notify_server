#!/usr/bin/python3
"""Standalone Piper and maintenance retain real leases through native writers."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('direct_consumer_fence_fixture',ROOT/'tools/test_installer_external_writer_fencing.py')
external=importlib.util.module_from_spec(spec);spec.loader.exec_module(external)
ENVIRONMENT=ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_piper_environment.py'
MAINTENANCE=ROOT/'slsmassnotifyserver/bin/sls_mass_notify_maintenance.sh'
PIPER_RUNNER=r'''
import importlib.util,os,pathlib,sys
base=pathlib.Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('private_piper_environment',sys.argv[1])
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
helper.RUNTIME=base/'helper';helper.DATA=str(base/'data')
# The fixture root and private inert replacement contain only a few bytes.
# Exercise the normal protected-source admission boundary before acquiring leases.
capacity = helper.RUNTIME/'sls_resource_capacity.py'
capacity.write_text(
    'def admit_piper_preparation_storage(selected, *, profile):\n'
    '    if selected != "/tmp" or profile is not None: raise ValueError("unexpected fixture workspace")\n'
    '    return {"schema":1,"temporary_directory":selected,"replacement_capacity_admitted":True,'
    '"filesystems":[{"paths":[selected]}]}\n'
)
capacity.chmod(0o644)
root=base/'runtime';root.mkdir(mode=0o755);(root/'venv').mkdir(mode=0o755)
(root/'venv/original').write_bytes(b'original private environment')
acquire=helper.guard_workers
def observed_guard():
    guard=acquire()
    (base/'keeper.pid').write_text(str(guard.pid))
    return guard
helper.guard_workers=observed_guard
def builder(stage,unused):
    (stage/'venv/replacement').write_bytes(b'inert validated replacement')
def validator(unused):
    helper.checked(['/usr/sbin/runuser','-u','asterisk','--','/usr/bin/python3','-I',
                    str(base/'native.py'),str(base/'native')],timeout=12)
helper.replace_environment(root,builder,validator)
'''


class StandalonePiperFencing(external.ExternalWriterFencingFixture,unittest.TestCase):
    def setUp(self):
        # Reuse exact native process/lease assertions; only the owning entrypoint
        # differs. The private builder does not install packages or import Piper.
        original=external.SHELL
        external.SHELL=r'''
mkdir "$2/helper"
cp "$3" "$2/helper/sls_install_guard.py"
exec /usr/bin/python3 -I "$2/piper-runner.py" "$4" "$2"
'''
        popen=subprocess.Popen
        def actual_entrypoint(command,*args,**kwargs):
            if command[:2]==['bash','-c'] and len(command)>=7 and command[3]=='fixture':
                private=Path(command[5])
                (private/'piper-runner.py').write_text(PIPER_RUNNER)
                source=(private/'native.py').read_text().replace(
                    "if target.endswith('.lock') or target.endswith('/audio-reservations.json'):",
                    'if int(path.name) > 2:')
                if self._testMethodName in ('test_waiter_sigkill_reaps_detached_native_descendant',
                                            'test_parent_and_keeper_death_reaps_detached_native_descendant'):
                    source=source.replace("while not (root/'release').exists():time.sleep(.01)",r'''
detached=os.fork()
if detached==0:
    os.setsid()
    (root/'detached.pid').write_text(str(os.getpid()))
    while not (root/'release-detached').exists():time.sleep(.01)
    (root/'detached-finished').write_text('unexpected detached write')
    os._exit(0)
while not (root/'release').exists():time.sleep(.01)
''')
                (private/'native.py').write_text(source)
                if self._testMethodName=='test_waiter_sigkill_retries_cleanup_before_lease_release':
                    # The helper is copied by the shell after this adapter;
                    # pass a private source with one transient proc read error.
                    guard=private/'transient-guard.py'
                    guard.write_text(external.GUARD.read_text().replace('def own_children(descriptor):',
                        '_inventory_reads = 0\ndef own_children(descriptor):\n'
                        '    global _inventory_reads\n    _inventory_reads += 1\n'
                        '    if _inventory_reads == 2: raise OSError("private transient inventory read")'))
                    command=[*command[:6],str(guard),*command[7:]]
                command=[*command,str(ENVIRONMENT)]
            return popen(command,*args,**kwargs)
        # The adapter only appends the fixed source path/write private runner;
        # all actual owner/native subprocesses are unmodified Popen executions.
        from unittest.mock import patch
        try:
            with patch.object(external.subprocess,'Popen',side_effect=actual_entrypoint):super().setUp()
        finally:external.SHELL=original

    def actual_guard_pid(self,parent):return parent

    def assert_fenced(self):
        for name in ('enterprise-worker.lock','announcement-activity.lock'):
            self.assertTrue(self.lock_is_held(name),'standalone Piper lost its native writer fence: '+name)

    def test_keeper_death_keeps_main_and_active_native_writer_fenced(self):
        self.assert_fenced();self.kill_actual_guard()
        self.assert_fenced()
        self.finish_native()
        stdout,stderr=self.main.communicate(timeout=6)
        self.assertEqual(self.main.returncode,0,stdout+stderr)
        self.assertFalse(self.lock_is_held('announcement-activity.lock'))

    def test_parent_sigint_keeps_native_validator_fenced_until_it_finishes(self):
        os.kill(self.main.pid,signal.SIGINT)
        # Python wait() first grants its child a250ms interrupt grace. Keep
        # the native child paused past that window before testing exclusion.
        deadline=time.monotonic()+.8
        while self.main.poll() is None and time.monotonic()<deadline:time.sleep(.01)
        self.assert_fenced()
        self.finish_native()
        stdout,stderr=self.main.communicate(timeout=6)
        self.assertNotEqual(self.main.returncode,0,stdout+stderr)
        self.assertFalse(self.lock_is_held('announcement-activity.lock'))

    def actual_run_waiter(self):
        pid=self.native['pid']
        for unused in range(16):
            status=Path('/proc/'+str(pid)+'/status').read_text()
            pid=int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
            self.assertGreater(pid,1,'Native child has no actual guarded run waiter')
            args=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
            if any(arg.endswith(b'/helper/sls_install_guard.py') for arg in args) and b'run' in args:
                return pid
        self.fail('Could not find the actual guarded run waiter')

    def assert_killed_waiter_containment(self, extra_pids=()):
        descriptors=[]
        try:
            for pid in (self.native['pid'],*extra_pids):descriptors.append(os.pidfd_open(pid))
            waiter=self.actual_run_waiter();waiter_fd=os.pidfd_open(waiter)
            try:
                self.assert_fenced()
                os.kill(waiter,signal.SIGKILL)
                self.assertTrue(select.select([waiter_fd],[],[],2)[0],'Actual run waiter did not die')
            finally:os.close(waiter_fd)
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                active=[fd for fd in descriptors if not select.select([fd],[],[],0)[0]]
                if not active:break
                self.assert_fenced()
                time.sleep(.005)
            self.assertTrue(all(select.select([fd],[],[],0)[0] for fd in descriptors),
                            'The dead waiter left an actual native writer running')
            stdout,stderr=self.main.communicate(timeout=6)
            self.assertNotEqual(self.main.returncode,0,stdout+stderr)
            self.assertFalse((self.root/'native/finished').exists(),'Orphaned native code wrote after cancellation')
            self.assertFalse(self.lock_is_held('announcement-activity.lock'))
        finally:
            for fd in descriptors:
                try:signal.pidfd_send_signal(fd,signal.SIGKILL)
                except ProcessLookupError:pass
                os.close(fd)

    def test_waiter_sigkill_reaps_native_before_lease_release(self):
        self.assert_killed_waiter_containment()

    def test_waiter_sigkill_reaps_detached_native_descendant(self):
        self.until(lambda:(self.root/'native/detached.pid').exists(),'Detached native fixture did not start')
        detached=int((self.root/'native/detached.pid').read_text())
        self.assertNotEqual(os.getpgid(detached),os.getpgid(self.native['pid']))
        self.assert_killed_waiter_containment((detached,))
        self.assertFalse((self.root/'native/detached-finished').exists())

    def test_waiter_sigkill_retries_cleanup_before_lease_release(self):
        self.assert_killed_waiter_containment()

    def test_parent_and_keeper_death_reaps_detached_native_descendant(self):
        self.until(lambda:(self.root/'native/detached.pid').exists(),'Detached native fixture did not start')
        detached=int((self.root/'native/detached.pid').read_text());descriptor=os.pidfd_open(detached)
        try:
            self.main.kill();self.main.wait(timeout=3);self.kill_actual_guard()
            self.assert_fenced()
            self.finish_native()
            deadline=time.monotonic()+4
            while not select.select([descriptor],[],[],0)[0] and time.monotonic()<deadline:
                self.assert_fenced();time.sleep(.005)
            self.assertTrue(select.select([descriptor],[],[],0)[0], 'Run waiter abandoned its detached native descendant')
            self.until(lambda:not self.lock_is_held('announcement-activity.lock'),'Run waiter leaked its lease after subtree reaping')
            self.assertFalse((self.root/'native/detached-finished').exists())
        finally:
            try:signal.pidfd_send_signal(descriptor,signal.SIGKILL)
            except ProcessLookupError:pass
            os.close(descriptor)

    def stop(self):
        # A failed assertion must also release a private native child in the
        # waiter's separate session before killing the owning fixture group.
        (self.root/'native/release').touch()
        super().stop()

    # These use the base actual native parent/keeper/signal assertions. Piper
    # owns no settings lease, so only its worker assertions are overridden.


ADMISSION_RUNNER=r'''
import ctypes,importlib.util,json,os,pathlib,sys
base=pathlib.Path(sys.argv[1]);state=int(sys.argv[2])
library=ctypes.CDLL(None,use_errno=True)
assert library.prctl(36,state,0,0,0)==0
spec=importlib.util.spec_from_file_location('private_piper_environment',base/'environment.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
helper.RUNTIME=base/'helper';helper.DATA=str(base/'data')
guard=helper.guard_workers();helper.CHECKED_WORKER_DESCRIPTORS=guard.sls_retained_descriptors
outcome={'status':'ok'}
try:
    helper.checked(['/usr/sbin/runuser','-u','asterisk','--','/usr/bin/python3','-I',
                    str(base/'native.py'),str(base/'native')],timeout=4)
except BaseException as error:
    outcome={'status':'refused','error':type(error).__name__}
finally:
    current=ctypes.c_int();assert library.prctl(37,ctypes.byref(current),0,0,0)==0
    outcome['subreaper']=current.value
    helper.CHECKED_WORKER_DESCRIPTORS=()
    guard.communicate('release\n',timeout=5)
    for descriptor in guard.sls_retained_descriptors:os.close(descriptor)
    (base/'outcome.json').write_text(json.dumps(outcome))
'''


class NativeExecutionAdmission(unittest.TestCase):
    """Wrong/missing control messages must never start mutable native code."""
    def run_admission(self, guard_change=None, environment_change=None, state=0):
        temporary=tempfile.TemporaryDirectory(dir='/run');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);root.chmod(0o755)
        account=pwd.getpwnam('asterisk')
        for name in ('data','native'):
            path=root/name;path.mkdir(mode=0o750);os.chown(path,account.pw_uid,account.pw_gid)
        (root/'helper').mkdir(mode=0o700)
        guard=external.GUARD.read_text();environment=ENVIRONMENT.read_text()
        if guard_change:
            before,after=guard_change;self.assertIn(before,guard);guard=guard.replace(before,after,1)
        if environment_change:
            before,after=environment_change;self.assertIn(before,environment);environment=environment.replace(before,after,1)
        (root/'helper/sls_install_guard.py').write_text(guard)
        (root/'environment.py').write_text(environment)
        (root/'runner.py').write_text(ADMISSION_RUNNER)
        (root/'native.py').write_text("import pathlib,sys\n(pathlib.Path(sys.argv[1])/'executed').write_text('mutable code executed')\n")
        (root/'native.py').chmod(0o644)
        result=subprocess.run(['/usr/bin/python3','-I',str(root/'runner.py'),str(root),str(state)],
                              capture_output=True,timeout=12)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        outcome=json.loads((root/'outcome.json').read_text())
        self.assertEqual(outcome['subreaper'],state,'Prior subreaper state was not restored')
        return root,outcome

    def assert_refused(self, **changes):
        root,outcome=self.run_admission(**changes)
        self.assertEqual(outcome['status'],'refused',outcome)
        self.assertFalse((root/'native/executed').exists(),'Mutable command started without valid admission')

    def test_malformed_identity_never_executes_native(self):
        self.assert_refused(guard_change=("{'schema': 1, 'waiter_pid': os.getpid(), 'native_pid': child.pid}",
                                        "{'schema': 2, 'waiter_pid': os.getpid(), 'native_pid': child.pid}"))

    def test_malformed_ack_never_executes_native(self):
        self.assert_refused(environment_change=("control.send(b'start')","control.send(b'invalid')"))

    def test_missing_ack_never_executes_native(self):
        self.assert_refused(environment_change=("control.send(b'start')","control.close()"))

    def test_waiter_sigkill_before_ack_never_executes_native(self):
        self.assert_refused(guard_change=("if control.recv(17) != b'start':",
                                        "os.kill(os.getpid(), signal.SIGKILL)\n                if control.recv(17) != b'start':"))

    def test_gate_exit_before_ack_never_executes_native(self):
        self.assert_refused(guard_change=("if os.read(descriptor, 16) != b'go\\n':","if True:"))

    def test_success_restores_disabled_and_enabled_subreaper_state(self):
        for state in (0,1):
            with self.subTest(state=state):
                root,outcome=self.run_admission(state=state)
                self.assertEqual(outcome['status'],'ok',outcome)
                self.assertTrue((root/'native/executed').exists())

    def test_refusal_restores_enabled_subreaper_state(self):
        self.assert_refused(state=1,environment_change=("control.send(b'start')","control.send(b'invalid')"))


class MaintenanceFencing(external.ExternalWriterFencingFixture,unittest.TestCase):
    def setUp(self):
        original=external.SHELL
        definitions=MAINTENANCE.read_text().split('[ "${EUID:-$(id -u)}" -eq 0 ] || exit 1',1)[0]
        external.SHELL=r'''
source "$2/maintenance-definitions.sh"
RUNTIME_DIR="$2/helper";CONFIG_FILE="$2/data/mass-notifications.config"
trap release_mutation_coordination EXIT
acquire_mutation_coordination
printf '%s\n' "$MUTATION_GUARD_PID" >"$2/keeper.pid"
run_without_maintenance_lock /usr/sbin/runuser -u asterisk -- /usr/bin/python3 -I "$2/native.py" "$2/native" &
native_waiter=$!
printf '%s\n' "$native_waiter" >"$2/waiter.pid"
wait "$native_waiter"
while [ ! -f "$2/release-main" ]; do sleep .01; done
MUTATION_VERIFIED=1
'''
        popen=subprocess.Popen
        def actual_entrypoint(command,*args,**kwargs):
            if command[:2]==['bash','-c'] and len(command)>=7 and command[3]=='fixture':
                private=Path(command[5]);runtime=private/'helper';runtime.mkdir(mode=0o700)
                shutil.copyfile(external.GUARD,runtime/'sls_install_guard.py')
                # Only the PBX idleness probe is inert. Guard/config fingerprint,
                # native runtime transition and cleanup run their real code.
                (runtime/'sls_install_idle.py').write_text('print("{}")\n')
                adapted=definitions.replace('/run/sls-maintenance-idle.XXXXXXXX',str(private/'idle.XXXXXXXX'))
                (private/'maintenance-definitions.sh').write_text(adapted)
            return popen(command,*args,**kwargs)
        from unittest.mock import patch
        try:
            with patch.object(external.subprocess,'Popen',side_effect=actual_entrypoint):super().setUp()
        finally:external.SHELL=original

    def actual_guard_pid(self,parent):
        pending=[parent];observed=[]
        while pending and len(observed)<32:
            pid=pending.pop();observed.append(pid)
            try:
                arguments=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
                children=Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()
            except FileNotFoundError:continue
            if any(arg.endswith(b'/helper/sls_install_guard.py') for arg in arguments) and b'hold' in arguments:
                return pid
            pending.extend(map(int,children))
        self.fail('actual maintenance Python guard not found: '+repr(observed))


if __name__=='__main__':unittest.main()
