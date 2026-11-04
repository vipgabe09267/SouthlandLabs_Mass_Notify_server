#!/usr/bin/env python3
"""Qualify embedded config I/O against private files and controlled changes."""
import hashlib
import importlib.util
import json
import shutil
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = (Path(__file__).resolve().parents[1] / "tools/install_release.sh").read_text()


def embedded(name, following):
    part = SOURCE[SOURCE.index(name + "() {"):SOURCE.index(following + "() {")]
    return part.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


HASH = embedded("safe_config_hash", "safe_config_restore")
SNAPSHOT = embedded("safe_config_snapshot", "safe_config_hash")
RESTORE = embedded("safe_config_restore", "snapshot_pending_config")
MUTATION = """import os
fixture_read = os.read
fixture_changed = False
def changed_read(fd, count):
    global fixture_changed
    if not fixture_changed:
        fixture_changed = True
        if os.environ['SLS_FIXTURE_CHANGE'] == 'grow':
            with open(os.environ['SLS_FIXTURE_SOURCE'], 'ab') as handle:
                handle.write(b'x' * (17 * 1024 * 1024))
        else:
            with open(os.environ['SLS_FIXTURE_SOURCE'], 'r+b') as handle:
                handle.write(b'z')
    return fixture_read(fd, count)
os.read = changed_read
"""


class InstallerConfigReaders(unittest.TestCase):
    def test_recovery_without_original_configuration_preserves_fresh_settings(self):
        helpers = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify'
        spec = importlib.util.spec_from_file_location('fresh_recovery_crypto', helpers / 'sls_config_crypto.py')
        crypto = importlib.util.module_from_spec(spec); spec.loader.exec_module(crypto)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            active = root / 'active'; original = crypto.encode_config({'fresh_fixture': True})
            active.write_bytes(original); active.chmod(0o640)
            program = r'''
source "$1"
CONFIG_FILE="$2/active"; CONFIG_SNAPSHOT=""; CONFIG_HASH_BEFORE=""
PENDING_CONFIG_PATH="$2/pending"; PENDING_CONFIG_SNAPSHOT=""
PENDING_CONFIG_STATE=absent; PENDING_CONFIG_HASH=""
RECOVERY_DIR="$2/recovery"; TRANSACTION_TOOL="$3"
verify_recovery_configuration || exit $?
[ -z "$CONFIG_RECOVERY_SNAPSHOT" ] && [ "$CONFIG_RECOVERY_HASH" = absent ]
'''
            result = subprocess.run(['bash', '-c', program, 'fixture',
                str(Path(__file__).resolve().parents[1] / 'tools/install_release.sh'),
                str(root), str(helpers / 'sls_install_transaction.py')],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(active.read_bytes(), original)
            self.assertFalse((recovery / 'configuration-mfa-recovery.json').exists())

    def test_recovery_preserves_a_monotonic_totp_counter_without_changing_original_evidence(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('mfa_configuration_transaction_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            original = {'operator_access': {'portal_enabled': True, 'accounts': [{'id': 'op_fixture', 'source': 'portal', 'enabled': True,
                'auth': {'totp_secret_enc': 'op1:' + 'A' * 80, 'totp_last_counter': 10}}]},
                'immediate_config_revisions': {'operator_access': 2}, 'unrelated': {'preserve': True}}
            current = json.loads(json.dumps(original))
            current['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
            current['immediate_config_revisions']['operator_access'] = 3
            snapshot = root / 'config.snapshot'; snapshot.write_text(json.dumps(original)); snapshot.chmod(0o600)
            active = root / 'active'; active.write_text(json.dumps(current)); active.chmod(0o640)
            before = snapshot.read_bytes(); digest = hashlib.sha256(before).hexdigest()
            try:
                prepare = getattr(journal, 'prepare_configuration_recovery', None)
                if prepare is None:
                    journal.assert_configuration_recoverable(recovery, digest, hashlib.sha256(active.read_bytes()).hexdigest(), 'absent', '', 'absent')
                    self.fail('No durable MFA-preserving configuration target was produced')
                target = prepare(recovery, digest, snapshot, active, 'absent', '', '', root / 'pending')
            except journal.TransactionError as error:
                self.fail('A normal MFA counter advance blocked protected recovery: ' + str(error))
            self.assertEqual(snapshot.read_bytes(), before)
            self.assertEqual(json.loads(Path(target['active_snapshot']).read_bytes()), current)
            self.assertEqual(target['active_sha256'], hashlib.sha256(active.read_bytes()).hexdigest())
            self.assertEqual(target['pending_sha256'], 'absent')

    def run_reader(self, body, settings, change=""):
        return subprocess.run(
            ["/usr/bin/python3", "-I", "-c", (MUTATION if change else "") + body],
            env={**os.environ, **settings, "SLS_FIXTURE_CHANGE": change},
            capture_output=True, text=True, timeout=3,
        )

    def test_hash_rejects_growth_and_same_size_changes_after_inspection(self):
        for change in ("grow", "rewrite"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                source = Path(name) / "config"; source.write_bytes(b"valid")
                result = self.run_reader(HASH, {"CONFIG_SOURCE_PATH": str(source), "SLS_FIXTURE_SOURCE": str(source)}, change)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_snapshot_rejects_concurrent_source_changes(self):
        for change in ("grow", "rewrite"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                source = Path(name) / "config"; source.write_bytes(b"valid")
                snapshot = Path(name) / "snapshot"; snapshot.touch(mode=0o600)
                result = self.run_reader(SNAPSHOT, {"CONFIG_SOURCE_PATH": str(source), "CONFIG_SNAPSHOT_PATH": str(snapshot), "SLS_FIXTURE_SOURCE": str(source)}, change)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_linked_snapshot_is_rejected_before_truncating_its_victim(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / "config"; source.write_bytes(b"valid")
            victim = Path(name) / "victim"; victim.write_bytes(b"preserved"); victim.chmod(0o600)
            target = Path(name) / "snapshot"; os.link(victim, target)
            result = self.run_reader(SNAPSHOT, {"CONFIG_SOURCE_PATH": str(source), "CONFIG_SNAPSHOT_PATH": str(target)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(victim.read_bytes(), b"preserved")

    def test_restore_rejects_changed_snapshot_before_promoting_anything(self):
        for change in ("grow", "rewrite"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                source = Path(name) / "snapshot"; source.write_bytes(b"valid"); source.chmod(0o600)
                target = Path(name) / "config"; target.write_bytes(b"preserved")
                result = self.run_reader(RESTORE, {"CONFIG_SNAPSHOT_PATH": str(source), "CONFIG_DESTINATION_PATH": str(target), "SLS_FIXTURE_SOURCE": str(source)}, change)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), b"preserved")
                self.assertFalse(list(Path(name).glob(".mass-notifications.config.restore.*")))

    def test_stable_configuration_roundtrip_retains_exact_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            body = b'{"private_fixture":"preserve"}\n'
            source = Path(name) / "config"; source.write_bytes(body)
            snapshot = Path(name) / "snapshot"; snapshot.touch(mode=0o600)
            result = self.run_reader(SNAPSHOT, {"CONFIG_SOURCE_PATH": str(source), "CONFIG_SNAPSHOT_PATH": str(snapshot)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(snapshot.read_bytes(), body)
            result = self.run_reader(HASH, {"CONFIG_SOURCE_PATH": str(source)})
            self.assertEqual(result.stdout.strip(), hashlib.sha256(body).hexdigest())
            result = self.run_reader(RESTORE, {"CONFIG_SNAPSHOT_PATH": str(snapshot), "CONFIG_DESTINATION_PATH": str(source)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(source.read_bytes(), body)


    def test_later_recovery_preserves_independent_active_and_pending_settings(self):
        for changed in ('active', 'pending', 'new-pending'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                for child in ('recovery', 'bootstrap'):
                    (root / child).mkdir(mode=0o700)
                shutil.copyfile(Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py', root / 'bootstrap/sls_install_transaction.py')
                original = b'original settings'
                active = root / 'config'; active.write_bytes(b'administrator settings' if changed == 'active' else original); active.chmod(0o640)
                pending = root / 'pending'; pending.write_bytes(b'administrator staged settings' if changed != 'active' else original); pending.chmod(0o640)
                for child in ('config.snapshot', 'pending.snapshot'):
                    (root / child).write_bytes(original); (root / child).chmod(0o600)
                before = (active.read_bytes(), pending.read_bytes())
                script = r"""
source "$1"
fixture="$2"; CONFIG_FILE="$fixture/config"; CONFIG_SNAPSHOT="$fixture/config.snapshot"
CONFIG_HASH_BEFORE="$(safe_config_hash "$CONFIG_SNAPSHOT")"
PENDING_CONFIG_PATH="$fixture/pending"; PENDING_CONFIG_SNAPSHOT="$fixture/pending.snapshot"
PENDING_CONFIG_HASH="$CONFIG_HASH_BEFORE"; PENDING_CONFIG_STATE=present
if [ "$3" = new-pending ]; then PENDING_CONFIG_STATE=absent; PENDING_CONFIG_HASH=""; PENDING_CONFIG_SNAPSHOT=""; fi
RECOVERY_DIR="$fixture/recovery"; TRANSACTION_TOOL="$fixture/bootstrap/sls_install_transaction.py"
INSTALL_TRANSACTION_DIR="$fixture"; RECOVERY_REQUEST_MODE=1; STATIC_MUTATION_STARTED=1
LOG_FILE="$fixture/log"; INSTALL_NOTIFICATION_SIDE_EFFECTS=0
log() { printf '%s\n' "$*" >>"$fixture/log"; }
rollback_module_install() { printf rollback >>"$fixture/unwanted-restoration"; ROLLBACK_VERIFIED=1; }
restore_freepbx_chown_permissions() { :; }
record_install_failure() { :; }
persist_install_transaction() { printf '%s\n' "$1" >>"$fixture/phases"; }
release_worker_coordination() { :; }
set +e
false
guard_config_on_exit
"""
                result = subprocess.run(['bash', '-c', script, 'fixture', str(Path(__file__).resolve().parents[1] / 'tools/install_release.sh'), name, changed], capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual((active.read_bytes(), pending.read_bytes()), before, 'Recovery overwrote a later administrator configuration change')
                self.assertFalse((root / 'unwanted-restoration').exists())
                self.assertTrue((root / 'config.snapshot').exists(), 'Conflict discarded the original protected snapshot')
                self.assertIn('recovery_failed', (root / 'phases').read_text())


    def test_recorded_configuration_writes_require_a_private_unbroken_chain(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('configuration_transaction_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first, second, third = b'original settings', b'profile change', b'branding change'
            digest = hashlib.sha256(first).hexdigest()
            journal.record_configuration_intent(root, digest, first, second)
            path = root / 'configuration-intents.json'
            before = path.read_bytes()
            with self.assertRaises(journal.TransactionError):
                journal.record_configuration_intent(root, digest, b'new administrator settings', third)
            self.assertEqual(path.read_bytes(), before)
            journal.record_configuration_intent(root, digest, second, third)
            for current in (digest, hashlib.sha256(second).hexdigest(), hashlib.sha256(third).hexdigest(), 'absent'):
                journal.assert_configuration_recoverable(root, digest, current, 'present', digest, 'absent')
            with self.assertRaises(journal.TransactionError):
                journal.assert_configuration_recoverable(root, digest, 'f' * 64, 'absent', '', 'absent')
            value = json.loads(path.read_bytes()); value['writes'][1]['before_sha256'] = '0' * 64
            path.write_text(json.dumps(value))
            with self.assertRaises(journal.TransactionError):
                journal.assert_configuration_recoverable(root, digest, digest, 'absent', '', 'absent')
            path.chmod(0o644)
            with self.assertRaises(journal.TransactionError):
                journal.configuration_intents(root, digest)

    def test_configuration_intent_retains_exact_afterimage_before_publishing_hash_chain(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('configuration_intent_afterimage_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); before = b'original encrypted settings'; after = b'installer encrypted settings'
            digest = hashlib.sha256(before).hexdigest()
            with mock.patch.object(journal, 'atomic', side_effect=OSError('Fixture intent publication interruption')):
                with self.assertRaises(OSError):
                    journal.record_configuration_intent(root, digest, before, after)
            image = root / ('configuration-intent-' + hashlib.sha256(after).hexdigest() + '.snapshot')
            self.assertTrue(image.exists(), 'Intent publication began without durable exact ciphertext evidence')
            self.assertEqual(image.read_bytes(), after)
            self.assertEqual(image.stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / 'configuration-intents.json').exists())

    def test_interrupted_configuration_image_never_publishes_partial_final_bytes(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('configuration_image_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); body = b'complete encrypted configuration evidence'
            path = root / ('configuration-mfa-' + hashlib.sha256(body).hexdigest() + '.snapshot')
            program = '''import importlib.util,os,pathlib,sys
spec=importlib.util.spec_from_file_location('crashed_image',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
os.fsync=lambda _fd:os._exit(77)
m.configuration_image(pathlib.Path(sys.argv[2]),'configuration-mfa-',b'complete encrypted configuration evidence')
'''
            result = subprocess.run(['/usr/bin/python3', '-I', '-c', program, str(helper), name], timeout=5)
            self.assertEqual(result.returncode, 77)
            self.assertFalse(path.exists(), 'A kill before durable completion exposed a final image name')
            published = journal.configuration_image(root, 'configuration-mfa-', body)
            self.assertEqual(published.read_bytes(), body)
            inode = published.stat().st_ino
            self.assertEqual(journal.configuration_image(root, 'configuration-mfa-', body).stat().st_ino, inode)
            published.write_bytes(b'contradictory evidence')
            with self.assertRaises(journal.TransactionError): journal.configuration_image(root, 'configuration-mfa-', body)
            self.assertEqual(published.read_bytes(), b'contradictory evidence')

    def test_mfa_after_installer_write_requires_exact_afterimage_and_survives_pre_restore_retry(self):
        self.assertEqual(os.environ.get('SLS_TEST_NAMESPACE'), 'entered', 'Use the official isolated runner')
        directory = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify'
        def load(name):
            spec = importlib.util.spec_from_file_location('fixture_' + name, directory / (name + '.py'))
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
        journal, crypto = load('sls_install_transaction'), load('sls_config_crypto')
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            original = {'deployment_profile': 'standard', 'operator_access': {'portal_enabled': True, 'accounts': [{'id': 'op_fixture',
                'source': 'portal', 'enabled': True, 'auth': {'totp_secret_enc': 'op1:' + 'A' * 80, 'totp_last_counter': 10}}]},
                'immediate_config_revisions': {'operator_access': 2}, 'unrelated': True}
            before = json.dumps(original).encode(); snapshot = root / 'config.snapshot'
            snapshot.write_bytes(before); snapshot.chmod(0o600); digest = hashlib.sha256(before).hexdigest()
            approved = json.loads(json.dumps(original)); approved['deployment_profile'] = 'lite'
            encoded = json.dumps(approved).encode(); journal.record_configuration_intent(recovery, digest, before, encoded)
            chain = (recovery / 'configuration-intents.json').read_bytes()
            image = recovery / ('configuration-intent-' + hashlib.sha256(encoded).hexdigest() + '.snapshot')
            image.unlink()  # Legacy transactions have hash-only intentions.
            active = root / 'active'; current = json.loads(json.dumps(approved))
            current['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
            current['immediate_config_revisions']['operator_access'] = 3
            active.write_text(json.dumps(current)); active.chmod(0o640)
            arguments = (recovery, digest, snapshot, active, 'absent', '', '', root / 'pending')
            with self.assertRaises(journal.TransactionError): journal.prepare_configuration_recovery(*arguments)
            self.assertFalse((recovery / 'configuration-mfa-recovery.json').exists())
            journal.configuration_image(recovery, 'configuration-intent-', encoded)
            target = journal.prepare_configuration_recovery(*arguments)
            expected = json.loads(json.dumps(original))
            expected['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
            expected['immediate_config_revisions']['operator_access'] = 3
            self.assertEqual(crypto.read_config(target['active_snapshot']), expected)
            self.assertEqual(journal.prepare_configuration_recovery(*arguments), target,
                             'Retry before target restoration lost its durable MFA cursor')
            current['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 12
            current['immediate_config_revisions']['operator_access'] = 4
            active.write_text(json.dumps(current))
            newer = journal.prepare_configuration_recovery(*arguments)
            self.assertEqual(crypto.read_config(newer['active_snapshot'])['operator_access']['accounts'][0]['auth']['totp_last_counter'], 12)
            self.assertEqual(snapshot.read_bytes(), before)
            self.assertEqual((recovery / 'configuration-intents.json').read_bytes(), chain)

    def test_mfa_target_publication_failure_preserves_live_and_original_configuration(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('mfa_storage_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            original = {'operator_access': {'portal_enabled': True, 'accounts': [{'id': 'op_fixture', 'source': 'portal', 'enabled': True,
                'auth': {'totp_secret_enc': 'op1:' + 'A' * 80, 'totp_last_counter': 10}}]}, 'immediate_config_revisions': {'operator_access': 2}}
            snapshot = root / 'config.snapshot'; snapshot.write_text(json.dumps(original)); snapshot.chmod(0o600)
            current = json.loads(json.dumps(original)); current['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
            current['immediate_config_revisions']['operator_access'] = 3
            active = root / 'active'; active.write_text(json.dumps(current)); active.chmod(0o640)
            before = (snapshot.read_bytes(), active.read_bytes())
            arguments = (recovery, hashlib.sha256(before[0]).hexdigest(), snapshot, active, 'absent', '', '', root / 'pending')
            with mock.patch.object(journal.os, 'fsync', side_effect=OSError('Fixture storage failure')):
                with self.assertRaises(journal.TransactionError): journal.prepare_configuration_recovery(*arguments)
            self.assertFalse((recovery / 'configuration-mfa-recovery.json').exists())
            self.assertEqual((snapshot.read_bytes(), active.read_bytes()), before)
            target = journal.prepare_configuration_recovery(*arguments)
            self.assertEqual(Path(target['active_snapshot']).read_bytes(), before[1])

    def test_ordinary_recovery_can_restore_missing_pending_but_mfa_merge_cannot_invent_it(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('pending_absence_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            settings = {'operator_access': {'portal_enabled': True, 'accounts': [{'id': 'op_fixture', 'source': 'portal', 'enabled': True,
                'auth': {'totp_secret_enc': 'op1:' + 'A' * 80, 'totp_last_counter': 10}}]}, 'immediate_config_revisions': {'operator_access': 2}}
            body = json.dumps(settings).encode(); digest = hashlib.sha256(body).hexdigest()
            snapshot = root / 'config.snapshot'; snapshot.write_bytes(body); snapshot.chmod(0o600)
            pending_snapshot = root / 'pending.snapshot'; pending_snapshot.write_bytes(body); pending_snapshot.chmod(0o600)
            active = root / 'active'; active.write_bytes(body); active.chmod(0o640)
            args = (recovery, digest, snapshot, active, 'present', digest, pending_snapshot, root / 'pending')
            try: target = journal.prepare_configuration_recovery(*args)
            except journal.TransactionError as error: self.fail('Ordinary approved missing-file recovery regressed: ' + str(error))
            self.assertEqual(target['pending_snapshot'], str(pending_snapshot))
            self.assertEqual(target['pending_sha256'], digest)
            settings['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
            settings['immediate_config_revisions']['operator_access'] = 3
            active.write_text(json.dumps(settings))
            with self.assertRaises(journal.TransactionError): journal.prepare_configuration_recovery(*args)
            self.assertFalse((recovery / 'configuration-mfa-recovery.json').exists())

    def test_saved_paired_mfa_target_handles_active_absence_but_preserves_missing_pending_conflict(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('saved_mfa_absence_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); recovery = root / 'recovery'; recovery.mkdir(mode=0o700)
            original = {'operator_access': {'portal_enabled': True, 'accounts': [{'id': 'op_fixture', 'source': 'portal', 'enabled': True,
                'auth': {'totp_secret_enc': 'op1:' + 'A' * 80, 'totp_last_counter': 10}}]}, 'immediate_config_revisions': {'operator_access': 2}}
            staged = json.loads(json.dumps(original)); staged['staged_setting'] = 'preserve'; staged['immediate_config_revisions']['operator_access'] = 5
            snapshots = []; hashes = []
            for label, settings in [('config', original), ('pending', staged)]:
                path = root / (label + '.snapshot'); path.write_text(json.dumps(settings)); path.chmod(0o600)
                snapshots.append(path); hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
            active, pending = root / 'active', root / 'pending'
            for path, settings in [(active, original), (pending, staged)]:
                settings = json.loads(json.dumps(settings))
                settings['operator_access']['accounts'][0]['auth']['totp_last_counter'] = 11
                settings['immediate_config_revisions']['operator_access'] = 6
                path.write_text(json.dumps(settings)); path.chmod(0o640)
            arguments = (recovery, hashes[0], snapshots[0], active, 'present', hashes[1], snapshots[1], pending)
            target = journal.prepare_configuration_recovery(*arguments)
            pending_bytes = pending.read_bytes(); active.unlink()
            self.assertEqual(journal.prepare_configuration_recovery(*arguments), target)
            self.assertEqual(json.loads(Path(target['active_snapshot']).read_bytes())['operator_access']['accounts'][0]['auth']['totp_last_counter'], 11)
            self.assertEqual(pending.read_bytes(), pending_bytes)
            pending.unlink()
            with self.assertRaises(journal.TransactionError): journal.prepare_configuration_recovery(*arguments)
            self.assertFalse(active.exists()); self.assertFalse(pending.exists())

    def test_configuration_snapshot_retention_is_repeatable(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); transaction = root / 'transaction'; transaction.mkdir(mode=0o700)
            (root / 'config').write_bytes(b'late fresh-install snapshot'); (root / 'config').chmod(0o600)
            script = r"""
source "$1"
INSTALL_TRANSACTION_DIR="$2/transaction"; CONFIG_SNAPSHOT="$2/config"
TRANSACTION_TOOL="$3"
retain_configuration_snapshots
retain_configuration_snapshots
printf '%s' "$CONFIG_SNAPSHOT"
"""
            result = subprocess.run(['bash', '-c', script, 'fixture', str(Path(__file__).resolve().parents[1] / 'tools/install_release.sh'), name,
                str(Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py')], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((transaction / 'config.snapshot').read_bytes(), b'late fresh-install snapshot')
            self.assertEqual(result.stdout, str(transaction / 'config.snapshot'))

    def test_retention_storage_failure_keeps_original_temporary_and_stops_the_shell(self):
        for failing in ('file','directory'):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as name:
                root=Path(name);transaction=root/'transaction';transaction.mkdir(mode=0o700)
                source=root/'config';source.write_bytes(b'original encrypted configuration');source.chmod(0o600)
                wrapper=root/'python-wrapper.py'
                wrapper.write_text('''import os,sys
real_sync=os.fsync
def checked_sync(fd):
    if os.readlink('/proc/self/fd/'+str(fd))==os.environ['FAIL_SYNC_TARGET']:
        with open(os.environ['FAIL_SYNC_TRACE'],'w') as trace:trace.write('reached')
        raise OSError('Fixture durable storage failure')
    return real_sync(fd)
os.fsync=checked_sync
exec(compile(sys.stdin.buffer.read(),'<instrumented installer input>','exec'))
''')
                installer=root/'installer.sh'
                installer.write_text(SOURCE.replace('/usr/bin/python3 -I - ', '/usr/bin/python3 -I '+shlex.quote(str(wrapper))+' '))
                code=r'''source "$1"
INSTALL_TRANSACTION_DIR="$2/transaction";CONFIG_SNAPSHOT="$2/config";TRANSACTION_TOOL="$3"
retain_configuration_snapshots
printf unsafe-next-stage > "$2/advanced"
'''
                result=subprocess.run(['bash','-c',code,'fixture',str(installer),name,
                    str(Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py')],
                    env={**os.environ,'FAIL_SYNC_TARGET':str(transaction/'config.snapshot') if failing=='file' else str(transaction),'FAIL_SYNC_TRACE':str(root/'sync-trace')},
                    capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertEqual((root/'sync-trace').read_text(),'reached')
                self.assertFalse((root/'advanced').exists())
                self.assertTrue(source.exists(),'Original snapshot was removed before durable retention completed')
                self.assertEqual(source.read_bytes(),b'original encrypted configuration')

    def test_durable_recovery_inputs_propagate_storage_failure_before_mutation(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('durable_inputs_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            transaction = Path(name) / 'transaction'; transaction.mkdir(mode=0o700)
            recovery = transaction / 'sls-mass-notify-recovery.ABC123'; recovery.mkdir(mode=0o700)
            for path in (transaction/'config.snapshot', recovery/'idle-before.json', recovery/'module-registration.json'):
                path.write_bytes(b'{"schema":1}'); path.chmod(0o600)
            original = {path: (path.stat().st_ino,path.read_bytes()) for path in recovery.iterdir()}
            synced = []; real_sync = os.fsync
            def failed_sync(fd):
                target = os.readlink('/proc/self/fd/' + str(fd)); synced.append(target)
                if target.endswith('/module-registration.json'):
                    raise OSError('Fixture storage refused recovery metadata flush')
                return real_sync(fd)
            with mock.patch.object(journal.os, 'fsync', side_effect=failed_sync):
                with self.assertRaisesRegex(OSError, 'storage refused'):
                    journal.sync_recovery_inputs(transaction,recovery,transaction/'config.snapshot','')
            self.assertTrue(any(path.endswith('/idle-before.json') for path in synced))
            for path, before in original.items():self.assertEqual((path.stat().st_ino,path.read_bytes()),before)
            synced.clear()
            def record_sync(fd):
                synced.append(os.readlink('/proc/self/fd/' + str(fd)));return real_sync(fd)
            with mock.patch.object(journal.os, 'fsync', side_effect=record_sync):
                journal.sync_recovery_inputs(transaction,recovery,transaction/'config.snapshot','')
            self.assertTrue({str(transaction/'config.snapshot'),str(recovery/'idle-before.json'),
                             str(recovery/'module-registration.json'),str(recovery),str(transaction)}.issubset(synced))
            self.assertEqual(synced[-2:],[str(recovery),str(transaction)])

    def test_durable_recovery_inputs_refuse_missing_unsafe_or_outside_evidence(self):
        helper = Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py'
        spec = importlib.util.spec_from_file_location('unsafe_inputs_fixture', helper)
        journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
        with tempfile.TemporaryDirectory() as name:
            transaction=Path(name)/'transaction';transaction.mkdir(mode=0o700)
            recovery=transaction/'sls-mass-notify-recovery.ABC123';recovery.mkdir(mode=0o700)
            for path in (recovery/'idle-before.json', recovery/'module-registration.json'):
                path.write_bytes(b'{"schema":1}');path.chmod(0o600)
            bad=recovery/'module-registration.json';body=bad.read_bytes()
            for kind in ('missing','symlink','hardlink','public','empty','malformed'):
                with self.subTest(kind=kind):
                    if bad.exists() or bad.is_symlink():bad.unlink()
                    victim=Path(name)/('victim-'+kind);victim.write_bytes(body);victim.chmod(0o600)
                    if kind=='symlink':bad.symlink_to(victim)
                    elif kind=='hardlink':os.link(victim,bad)
                    elif kind!='missing':bad.write_bytes(b'' if kind=='empty' else b'broken' if kind=='malformed' else body);bad.chmod(0o644 if kind=='public' else 0o600)
                    with self.assertRaises((OSError,journal.TransactionError,ValueError)):
                        journal.sync_recovery_inputs(transaction,recovery,'','')
                    self.assertEqual(victim.read_bytes(),body)
            if bad.exists() or bad.is_symlink():bad.unlink()
            bad.write_bytes(body);bad.chmod(0o600)
            outside=Path(name)/'outside';outside.write_bytes(body);outside.chmod(0o600)
            with self.assertRaises(journal.TransactionError):
                journal.sync_recovery_inputs(transaction,recovery,outside,'')


if __name__ == "__main__":
    unittest.main()
