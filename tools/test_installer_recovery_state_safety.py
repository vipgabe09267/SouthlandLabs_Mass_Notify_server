#!/usr/bin/python3
"""Installer recovery must preserve concurrent settings and shared PBX files.

These behavioral regressions run only in the official disposable namespaces.
The real shell, crypto/recovery helpers and PHP MFA writer execute; external PBX
registration/service phases use the existing narrow fixture adapters.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


transaction = load('safe_transaction', HELPERS / 'sls_install_transaction.py')
static_fixture = load('safe_static_fixture', ROOT / 'tools/test_installer_recovery.py')
mfa_fixture = load('safe_mfa_fixture', ROOT / 'tools/test_installer_mfa_recovery.py')


class ConfigurationPreparation(unittest.TestCase):
    def test_original_fresh_absence_keeps_its_nondeleting_recovery_contract(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            result = transaction.prepare_configuration_recovery('', '', '', root / 'active.config',
                'absent', '', '', root / 'pending.config')
            self.assertEqual(result['active_sha256'], 'absent')
            self.assertEqual(list(root.iterdir()), [])

    def test_metadata_only_preparation_accepts_exact_original_without_relative_authority(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            active = root / 'active.config'
            snapshot = root / 'config.snapshot'
            original = b'{"preserve":"exact original"}\n'
            active.write_bytes(original); active.chmod(0o640)
            snapshot.write_bytes(original); snapshot.chmod(0o600)
            digest = hashlib.sha256(original).hexdigest()
            result = transaction.prepare_configuration_recovery(
                '', digest, snapshot, active, 'absent', '', '', root / 'pending.config')
            self.assertEqual(result['active_sha256'], digest)
            self.assertEqual(result['active_snapshot'], str(snapshot))
            self.assertEqual(active.read_bytes(), original)
            self.assertEqual(snapshot.read_bytes(), original)
            self.assertEqual(set(root.iterdir()), {active, snapshot})

    def test_metadata_only_preparation_preserves_unrecognized_live_edit(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name); active = root / 'active.config'; snapshot = root / 'config.snapshot'
            original = b'{"preserve":"original"}\n'; changed = b'{"preserve":"administrator edit"}\n'
            active.write_bytes(changed); active.chmod(0o640)
            snapshot.write_bytes(original); snapshot.chmod(0o600)
            with self.assertRaises(transaction.TransactionError):
                transaction.prepare_configuration_recovery('', hashlib.sha256(original).hexdigest(),
                    snapshot, active, 'absent', '', '', root / 'pending.config')
            self.assertEqual(active.read_bytes(), changed)
            self.assertEqual(snapshot.read_bytes(), original)

    def test_metadata_only_preparation_refuses_unknown_pending_state(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name); active = root / 'active.config'; snapshot = root / 'config.snapshot'
            original = b'{"preserve":"exact original"}\n'
            active.write_bytes(original); active.chmod(0o640)
            snapshot.write_bytes(original); snapshot.chmod(0o600)
            with self.assertRaises(transaction.TransactionError):
                transaction.prepare_configuration_recovery('', hashlib.sha256(original).hexdigest(),
                    snapshot, active, 'unknown', '', '', root / 'pending.config')
            self.assertEqual(active.read_bytes(), original)
            self.assertEqual(snapshot.read_bytes(), original)


class SharedNativeFiles(unittest.TestCase):
    def fixture(self):
        fixture = static_fixture.Fixture(methodName='test_roundtrip_preserves_data_config_images_and_concurrent_unrelated_cron')
        fixture.setUp(); self.addCleanup(fixture.tearDown)
        return fixture

    def test_unrelated_shared_file_edit_blocks_restore_before_any_static_or_cron_write(self):
        fixture = self.fixture(); fixture.snapshot()
        edited = fixture.file('/etc/asterisk/extensions_custom.conf',
                              b'original dialplan\n; independent administrator edit\n')
        worker = fixture.file(static_fixture.r.RUNTIME + '/worker.py', b'candidate worker\n', 0o755)
        cron_before = (fixture.cron, fixture.user_cron)
        with self.assertRaises(static_fixture.r.RecoveryError):
            fixture.helper.restore()
        self.assertEqual(edited.read_bytes(), b'original dialplan\n; independent administrator edit\n')
        self.assertEqual(worker.read_bytes(), b'candidate worker\n')
        self.assertEqual((fixture.cron, fixture.user_cron), cron_before)

    def test_originally_absent_shared_file_with_admin_content_is_never_deleted(self):
        fixture = self.fixture(); fixture.snapshot()
        edited = fixture.file('/etc/asterisk/manager_custom.conf', b'[independent-account]\nread=system\n')
        with self.assertRaises(static_fixture.r.RecoveryError):
            fixture.helper.restore()
        self.assertEqual(edited.read_bytes(), b'[independent-account]\nread=system\n')

    def test_exact_owned_block_update_can_restore_original_shared_file(self):
        fixture = self.fixture(); fixture.snapshot()
        edited = fixture.file('/etc/asterisk/extensions_custom.conf', b'original dialplan\n\n'
            b'; BEGIN SLS Mass Notifications Dialplan\n[synthetic-sll-context]\n'
            b'; END SLS Mass Notifications Dialplan\n')
        self.assertTrue(fixture.helper.restore()['ok'])
        self.assertEqual(edited.read_bytes(), b'original dialplan\n')
        self.assertTrue(fixture.helper.verify()['snapshot_verified'])

    def test_shared_edit_after_preflight_is_not_replaced_by_later_write(self):
        fixture = self.fixture(); fixture.snapshot()
        path = fixture.file('/etc/asterisk/extensions_custom.conf', b'original dialplan\n\n'
            b'; BEGIN SLS Mass Notifications Dialplan\n[synthetic-sll-context]\n'
            b'; END SLS Mass Notifications Dialplan\n')
        changed = path.read_bytes() + b'; administrator edit after preflight\n'
        actual_write = fixture.helper.write_at
        def injected_write(parent, name, *arguments, **options):
            if name == 'extensions_custom.conf': path.write_bytes(changed)
            return actual_write(parent, name, *arguments, **options)
        fixture.helper.write_at = injected_write
        with self.assertRaises(static_fixture.r.RecoveryError): fixture.helper.restore()
        self.assertEqual(path.read_bytes(), changed)

    def test_shared_edit_after_preflight_is_not_deleted_by_later_remove(self):
        fixture = self.fixture(); fixture.snapshot()
        path = fixture.file('/etc/asterisk/manager_custom.conf',
            b'; BEGIN SLS Mass Notifications AMI\n[synthetic-sll-account]\n; END SLS Mass Notifications AMI\n')
        changed = path.read_bytes() + b'; administrator account after preflight\n'
        actual_remove = fixture.helper.remove
        def injected_remove(name, *arguments, **options):
            if name == '/etc/asterisk/manager_custom.conf': path.write_bytes(changed)
            return actual_remove(name, *arguments, **options)
        fixture.helper.remove = injected_remove
        with self.assertRaises(static_fixture.r.RecoveryError): fixture.helper.restore()
        self.assertEqual(path.read_bytes(), changed)

    def test_same_bytes_with_replaced_shared_inode_are_not_adopted_after_preflight(self):
        fixture = self.fixture(); fixture.snapshot()
        path = fixture.file('/etc/asterisk/extensions_custom.conf', b'original dialplan\n')
        actual_write = fixture.helper.write_at; replaced = []
        def injected_write(parent, name, *arguments, **options):
            if name == 'extensions_custom.conf':
                temporary = path.with_name('administrator-replacement.conf')
                temporary.write_bytes(path.read_bytes()); temporary.chmod(0o644)
                os.replace(temporary, path); replaced.append(path.stat().st_ino)
            return actual_write(parent, name, *arguments, **options)
        fixture.helper.write_at = injected_write
        with self.assertRaises(static_fixture.r.RecoveryError): fixture.helper.restore()
        self.assertEqual(path.stat().st_ino, replaced[0])
        self.assertEqual(path.read_bytes(), b'original dialplan\n')


class KeeperFencing(unittest.TestCase):
    def test_successful_inspector_cannot_commit_after_its_keeper_dies(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            inspector = root / 'inert-idle.py'
            inspector.write_text('import os,signal\nos.kill(int(os.environ["FIXTURE_KEEPER_PID"]),signal.SIGKILL)\nprint("{\\"ok\\":true}")\n')
            shell = r'''
source "$1"
DATA_DIR="$2"; RECOVERY_DIR="$2"; WORKER_GUARD_TOOL="$3"; IDLE_TOOL="$4"
trap release_worker_coordination EXIT
acquire_worker_coordination
export FIXTURE_KEEPER_PID="$WORKER_LOCK_PID"
verify_install_idle_history
printf 'unsafe-success\n'
'''
            result = subprocess.run(['bash', '-c', shell, 'fixture', str(ROOT / 'tools/install_release.sh'),
                str(root), str(HELPERS / 'sls_install_guard.py'), str(inspector)], capture_output=True,
                text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('unsafe-success', result.stdout)

    def test_live_keeper_check_confirms_held_lease_and_rejects_replaced_mutex(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            process = subprocess.Popen([sys.executable, '-I', str(HELPERS / 'sls_install_guard.py'),
                '--data', str(root), '--settings', '--timeout', '2', 'hold'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                self.assertEqual(process.stdout.readline(), b'ready\n')
                process.stdin.write(b'check\n'); process.stdin.flush()
                self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                self.assertEqual(process.stdout.readline(), b'checked\n')
                path = root / 'announcement-activity.lock'
                path.rename(root / 'original-activity.lock')
                path.write_bytes(b''); path.chmod(0o640)
                process.stdin.write(b'check\n'); process.stdin.flush()
                process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0)
            finally:
                if process.poll() is None: process.kill()
                process.communicate(timeout=5)


class MfaPreservation(unittest.TestCase):
    def test_missing_established_active_cannot_restore_an_unknown_consumed_floor(self):
        fixture = mfa_fixture.MfaRecoveryIntegration(methodName='test_actual_totp_login_is_accepted_by_recovery')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        (fixture.data / 'mass-notifications.pending.config').unlink()
        consumed = fixture.run_php('login'); self.assertTrue(consumed['accepted'])
        active = fixture.data / 'mass-notifications.config'
        active.unlink()  # Independent loss after a newer real MFA consumption.
        original = fixture.original_snapshots['config.snapshot']
        with self.assertRaises(transaction.TransactionError):
            transaction.prepare_configuration_recovery(fixture.transaction / 'recovery',
                hashlib.sha256(original).hexdigest(), fixture.transaction / 'config.snapshot', active,
                'absent', '', '', fixture.data / 'mass-notifications.pending.config')
        self.assertFalse(active.exists())
        self.assertEqual((fixture.transaction / 'config.snapshot').read_bytes(), original)

    def test_final_verifier_never_restores_an_old_consumed_counter(self):
        fixture = mfa_fixture.MfaRecoveryIntegration(methodName='test_actual_totp_login_is_accepted_by_recovery')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        consumed = fixture.run_php('login'); self.assertTrue(consumed['accepted'])
        advanced = fixture.settings()
        setup = mfa_fixture.GUARD.rsplit('verify_recovery_configuration', 1)[0]
        setup = setup.replace('RECOVERY_REQUEST_MODE=1', 'RECOVERY_REQUEST_MODE=0')
        commands = '\nINSTALL_BOOTSTRAP_DIR="$fixture/bootstrap"\nensure_data_directory() { :; }\nverify_config_unchanged\n'
        result = subprocess.run(['bash', '-c', setup + commands, 'fixture',
            str(ROOT / 'tools/install_release.sh'), str(fixture.root)], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.settings(), advanced)
        self.assertFalse(fixture.run_php('login', consumed['code'])['accepted'])

    def test_ordinary_failed_exit_preserves_monotonic_mfa_like_manual_recovery(self):
        fixture = mfa_fixture.MfaRecoveryIntegration(methodName='test_actual_totp_login_is_accepted_by_recovery')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        consumed = fixture.run_php('login'); self.assertTrue(consumed['accepted'])
        advanced = fixture.settings()
        setup = mfa_fixture.GUARD.rsplit('verify_recovery_configuration', 1)[0]
        setup = setup.replace('RECOVERY_REQUEST_MODE=1', 'RECOVERY_REQUEST_MODE=0')
        result = subprocess.run(['bash', '-c', setup + mfa_fixture.EXIT_GUARD, 'fixture',
            str(ROOT / 'tools/install_release.sh'), str(fixture.root)], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.settings(), advanced)
        self.assertFalse(fixture.run_php('login', consumed['code'])['accepted'])


if __name__ == '__main__':
    unittest.main()
