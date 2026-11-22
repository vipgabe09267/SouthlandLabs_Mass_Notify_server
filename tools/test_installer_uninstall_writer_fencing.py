#!/usr/bin/python3
"""Uninstall native writers retain leases without exposing them to PHP."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('external_fencing_fixture',
    ROOT / 'tools/test_installer_external_writer_fencing.py')
external = importlib.util.module_from_spec(spec)
spec.loader.exec_module(external)

UNINSTALL_SHELL = r'''
source "${1%/*}/uninstall_release.sh"
DATA_DIR="$2/data"; RECOVERY_SIGNER_DIR="$2/helper"
mkdir "$RECOVERY_SIGNER_DIR"
cp "$3" "$RECOVERY_SIGNER_DIR/sls_install_guard.py"
trap release_uninstall_workers EXIT
acquire_uninstall_workers
printf '%s\n' "$UNINSTALL_WORKER_PID" >"$2/keeper.pid"
run_as_asterisk /usr/bin/python3 -I "$2/native.py" "$2/native" &
native_waiter=$!
printf '%s\n' "$native_waiter" >"$2/waiter.pid"
wait "$native_waiter"
while [ ! -f "$2/release-main" ]; do sleep .01; done
'''


class UninstallWriterFencing(external.ExternalWriterFencing):
    def setUp(self):
        original = external.SHELL
        external.SHELL = UNINSTALL_SHELL
        try:
            super().setUp()
        finally:
            external.SHELL = original

    def actual_guard_pid(self, parent):
        pending = [parent]
        observed = []
        while pending and len(observed) < 32:
            pid = pending.pop()
            observed.append(pid)
            try:
                arguments = Path('/proc/' + str(pid) + '/cmdline').read_bytes().split(b'\0')
                children = Path('/proc/' + str(pid) + '/task/' + str(pid) + '/children').read_text().split()
            except FileNotFoundError:
                continue
            if any(arg.endswith(b'/helper/sls_install_guard.py') for arg in arguments) and b'hold' in arguments:
                return pid
            pending.extend(map(int, children))
        self.fail('Actual uninstall guard not found: ' + repr(observed))

    def assert_fenced(self):
        for name in ('enterprise-worker.lock', 'announcement-activity.lock'):
            self.assertTrue(self.lock_is_held(name), 'Native uninstall writer lost its fence: ' + name)
        # Native uninstall hooks can acquire the settings mutex themselves.
        self.assertFalse(self.lock_is_held('mass-notifications.config.lock'))


class UninstallGuardAdmission(unittest.TestCase):
    def test_explicit_purge_keeps_leased_anchors_through_final_native_verification(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            private=Path(name);data=private/'data';data.mkdir(mode=0o700)
            helper=private/'helper';helper.mkdir(mode=0o700)
            shutil.copyfile(external.GUARD,helper/'sls_install_guard.py')
            script=r'''
source "$1"
DATA_DIR="$2/data";RECOVERY_SIGNER_DIR="$2/helper";PURGE_CONFIG=1
trap release_uninstall_workers EXIT
acquire_uninstall_workers
remove_piper_wrapper() { :; }
remove_managed_sound_link() { :; }
remove_managed_path() { if [ "$1" = "$DATA_DIR" ]; then /bin/rm -rf -- "$DATA_DIR"; fi; }
remove_runtime_files
[ -d "$DATA_DIR" ] || { printf 'runtime removal erased still-required worker anchors\n' >&2; exit 81; }
assert_uninstall_workers
printf 'final-native-verification-complete\n'
purge_uninstall_data
[ ! -e "$DATA_DIR" ]
'''
            result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/uninstall_release.sh'),
                str(private)],capture_output=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn(b'final-native-verification-complete',result.stdout)
            self.assertFalse(data.exists())

    def test_named_mutex_replacement_cannot_pass_uninstall_pre_mutation_check(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            private=Path(name);data=private/'data';data.mkdir(mode=0o700)
            helper=private/'helper';helper.mkdir(mode=0o700)
            shutil.copyfile(external.GUARD,helper/'sls_install_guard.py')
            script=r'''
source "$1"
DATA_DIR="$2/data";RECOVERY_SIGNER_DIR="$2/helper"
trap release_uninstall_workers EXIT
acquire_uninstall_workers
mv "$DATA_DIR/announcement-activity.lock" "$DATA_DIR/original-activity.lock"
: >"$DATA_DIR/announcement-activity.lock"
chmod 640 "$DATA_DIR/announcement-activity.lock"
assert_uninstall_workers
printf 'unsafe-uninstall-mutation-authorized\n'
'''
            result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/uninstall_release.sh'),
                str(private)],capture_output=True,timeout=8)
            self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertNotIn(b'unsafe-uninstall-mutation-authorized',result.stdout)


if __name__ == '__main__':
    unittest.main()
