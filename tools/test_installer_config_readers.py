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
