#!/usr/bin/python3
"""Real signer lock and runtime UID with inert PHP/GPG execution boundaries."""
import base64
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import shlex
import signal
import select
import subprocess
import tempfile
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh').read_text()


class SignerDescriptors(unittest.TestCase):
    def until(self, predicate, message, seconds=5, process=None):
        deadline = time.monotonic()+seconds
        while not predicate() and time.monotonic() < deadline:
            time.sleep(.01)
        if not predicate() and process is not None and select.select([process.stderr], [], [], 0)[0]:
            message += '\nNative boundary stderr: '+os.read(process.stderr.fileno(),8192).decode(errors='replace')
        self.assertTrue(predicate(), message)

    def held(self, path):
        with path.open('rb') as handle:
            try: fcntl.flock(handle, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: return True
            return False

    @contextmanager
    def fixture(self, boundary, *, blocking=True, status=0, registration_pause=0):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-signer-native-fds-') as name:
            root = Path(name); root.chmod(0o755)
            native = root/'native'; native.mkdir(mode=0o750)
            os.chown(native, account.pw_uid, account.pw_gid)
            (root/'bin').mkdir(mode=0o755); (root/'bin').chmod(0o755)
            lock = root/'signing.lock'
            metadata = [account.pw_name, '/var/www/html', '/var/lib/asterisk/.gnupg', account.pw_dir, '/var/spool/asterisk']
            output = '\n'.join(base64.b64encode(value.encode()).decode() for value in metadata)+'\n'
            program = ('#!/usr/bin/python3\nimport json,os,signal,time\nfrom pathlib import Path\n'
                'root=Path('+repr(str(native))+')\nlock='+repr(str(lock))+'\n'
                'for value in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(value,signal.SIG_IGN)\n'
                'leases=[]\nfor path in Path("/proc/self/fd").iterdir():\n'
                ' try: target=os.readlink(path)\n except FileNotFoundError: continue\n'
                ' if target==lock: leases.append(int(path.name))\n'
                'body=__import__("sys").stdin.buffer.read()\n'
                '(root/"receipt.pending").write_text(json.dumps({"pid":os.getpid(),"uid":os.geteuid(),"leases":leases,"stdin":body.decode()}))\n'
                'os.replace(root/"receipt.pending",root/"receipt.json")\n'
                # Every fake native child stays alive until the parent has
                # registered its real pidfd and the independent root waiter.
                + 'while not (root/"release").exists(): time.sleep(.01)\n'
                + '(root/"finished").write_text("last native fixture write")\n'
                + ('print('+repr(output)+',end="")\n' if boundary=='metadata' else '')
                + 'raise SystemExit('+str(status)+')\n')
            for path in (root/'fake-php', root/'bin/gpg'):
                path.write_text(program); path.chmod(0o755)
            adapted = root/'signer.sh'
            adapted.write_text(SOURCE.replace('/usr/bin/php', shlex.quote(str(root/'fake-php'))))
            adapted.chmod(0o600)
            shell = r'''
source "$1"
LOCK_FILE="$2/signing.lock"; WORKDIR="$2/work"; mkdir "$WORKDIR"
PATH="$2/bin:$PATH"
FREEPBX_WEB_USER=asterisk; FREEPBX_GPG_HOME="$2/gpg"
acquire_signing_lock
case "$3" in
  metadata) load_freepbx_metadata; printf '%s\n%s\n' "$FREEPBX_WEB_USER" "$FREEPBX_WEB_ROOT" >"$2/metadata-result" ;;
  verify) verify_published_signature ;;
  gpg) printf 'actual private signer stdin\n' >"$2/input"; run_freepbx_gpg fixture "$2/input" "$2/output" --version ;;
  *) exit 93 ;;
esac
'''
            process = subprocess.Popen(['/bin/bash','-c',shell,'fixture',str(adapted),str(root),boundary],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            tracked = []
            try:
                self.until(lambda:(native/'receipt.json').exists(), 'The actual native signer boundary was never reached', process=process)
                receipt = json.loads((native/'receipt.json').read_text())
                self.assertEqual(receipt['uid'], account.pw_uid)
                if registration_pause:
                    time.sleep(registration_pause)
                pid = receipt['pid']
                waiter = None
                for _ in range(20):
                    try:
                        pidfd = os.pidfd_open(pid); tracked.append(pidfd)
                        details = Path('/proc/'+str(pid)+'/status').read_text()
                    except (ProcessLookupError, FileNotFoundError): break
                    if pid == process.pid: break
                    uid = int(next(line.split()[1] for line in details.splitlines() if line.startswith('Uid:')))
                    if uid == 0:
                        try: target = os.readlink('/proc/'+str(pid)+'/fd/9')
                        except FileNotFoundError: target = ''
                        if target == str(lock): waiter = pid; break
                    pid = int(next(line.split()[1] for line in details.splitlines() if line.startswith('PPid:')))
                    if pid <= 1: break
                self.assertIsNotNone(waiter, 'No live root signing waiter was registered before native release')
                if not blocking:
                    (native/'release').touch()
                yield process, root, native, lock, receipt, waiter
            finally:
                (native/'release').touch()
                try: process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    for pidfd in tracked:
                        try: signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        except ProcessLookupError: pass
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.communicate(timeout=5)
                for pidfd in tracked: os.close(pidfd)

    def test_fast_native_exit_waits_for_pidfd_registration(self):
        # Root bookkeeping may be descheduled after the atomic child receipt.
        # The fixture must keep that exact child and its root waiter alive until
        # their real pidfds have been registered, even for a fast success/failure.
        for boundary, status in (('metadata', 0), ('gpg', 0), ('verify', 23)):
            with self.subTest(boundary=boundary), self.fixture(
                    boundary, blocking=False, status=status, registration_pause=.1) as fixture:
                process, root, native, lock, receipt, waiter = fixture
                self.assertIsNotNone(waiter, 'Fast native boundary exited before root waiter registration')
                self.assertEqual(receipt['leases'], [])
                process.wait(timeout=3)
                self.assertEqual(process.returncode, status)

    def test_each_native_signer_boundary_has_no_unlock_capable_descriptor(self):
        for boundary in ('metadata','verify','gpg'):
            with self.subTest(boundary=boundary), self.fixture(boundary) as fixture:
                process, root, native, lock, receipt, waiter = fixture
                self.assertTrue(self.held(lock), 'The actual root signing lease was not held')
                self.assertEqual(receipt['leases'], [], 'Mutable native signer child inherited the real root signing lock')

    def test_root_waiter_retains_signing_lease_through_parent_death_and_signals(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signum), self.fixture('verify') as fixture:
                process, root, native, lock, receipt, waiter = fixture
                self.assertIsNotNone(waiter, 'No independent root waiter retains the actual signing lease')
                process.kill(); process.wait(timeout=3)
                os.kill(waiter, signum); time.sleep(.1)
                self.assertFalse((native/'finished').exists())
                self.assertTrue(self.held(lock), 'Interrupted root waiter released a live native signer lease')
                (native/'release').touch()
                self.until(lambda:(native/'finished').exists(), 'Native signer did not complete its final write')
                self.until(lambda:not self.held(lock), 'Completed native signer leaked the actual signing lease')

    def test_native_metadata_stdin_and_failure_status_are_preserved(self):
        with self.fixture('metadata', blocking=False) as fixture:
            process, root, native, lock, receipt, waiter = fixture
            process.wait(timeout=3)
            self.assertEqual(process.returncode, 0, 'Native metadata could not be read after its root waiter exited')
            self.assertEqual((root/'metadata-result').read_text(), 'asterisk\n/var/www/html\n')
        with self.fixture('gpg', blocking=False) as fixture:
            process, root, native, lock, receipt, waiter = fixture
            process.wait(timeout=3)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(receipt['stdin'], 'actual private signer stdin\n')
        with self.fixture('verify', blocking=False, status=23) as fixture:
            process, root, native, lock, receipt, waiter = fixture
            process.wait(timeout=3)
            self.assertEqual(process.returncode, 23)


if __name__ == '__main__': unittest.main()
