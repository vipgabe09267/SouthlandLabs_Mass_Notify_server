#!/usr/bin/python3
"""Authenticated history-loss decisions and retained original recovery evidence."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
from copy import deepcopy
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
SPEC = importlib.util.spec_from_file_location('history_transaction', BIN / 'sls_install_transaction.py')
j = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(j)


@unittest.skipUnless(os.geteuid() == 0, 'root-only authenticated recovery evidence')
class HistoryReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sll-history-review-', dir='/run')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'journal'
        self.transaction = j.begin(self.root)
        self.bootstrap = self.transaction / 'bootstrap'
        self.bootstrap.mkdir(mode=0o700)
        key = self.base / 'key'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(key)],
                       check=True, capture_output=True)
        public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout'],
                                check=True, capture_output=True).stdout
        self.public = public
        contents = {name: (BIN / name).read_bytes() for name in j.BOOTSTRAP_FILES}
        verifier = contents['sls_release_trust.py'].decode()
        start = verifier.index('ANCHOR_PEM = ')
        end = verifier.index('\n', start)
        verifier = verifier[:start] + 'ANCHOR_PEM = ' + repr(public) + verifier[end:]
        verifier = verifier.replace("DIRECTORY = Path('/var/lib/sls-mass-notify-trust')",
                                    'DIRECTORY = Path(' + repr(str(self.base / 'unused-policy')) + ')')
        contents['sls_release_trust.py'] = verifier.encode()
        for name, body in contents.items():
            (self.bootstrap / name).write_bytes(body)
            (self.bootstrap / name).chmod(0o600 if name.endswith('.pub') else 0o700)
        package = self.transaction / 'package.tgz'
        with tarfile.open(package, 'w:gz') as archive:
            for name, body in contents.items():
                entry = tarfile.TarInfo('slsmassnotifyserver/bin/sls_mass_notify/' + name)
                entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))
        installer = self.transaction / 'installer.sh'
        installer.write_bytes(b'original authenticated installer fixture')
        self.manifest = self.transaction / 'release-manifest.json'
        self.now = int(time.time())
        public_der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'],
                                    input=public, check=True, capture_output=True).stdout
        self.publisher_id = hashlib.sha256(public_der).hexdigest()
        self.manifest.write_text(json.dumps({
            'schema': 1, 'version': '0.1.8-beta', 'tag': 'slsmassnotifyserver-0.1.8-beta',
            'package': 'slsmassnotifyserver-0.1.8-beta.tgz',
            'installer_sha256': hashlib.sha256(installer.read_bytes()).hexdigest(),
            'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
            'signing': {'key_id': self.publisher_id, 'issued_at': self.now - 5, 'expires_at': self.now + 3600},
        }))
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key),
                        '-in', str(self.manifest), '-out', str(self.transaction / 'release-manifest.sig')],
                       check=True, capture_output=True)
        for name in ('installer.sh', 'package.tgz', 'release-manifest.json', 'release-manifest.sig'):
            (self.transaction / name).chmod(0o600)
        self.recovery = self.transaction / 'sls-mass-notify-recovery.ABC123'
        self.recovery.mkdir(mode=0o700)
        self.baseline = self.recovery / 'idle-before.json'
        hashes = {}
        for number in range(1, 23):
            token = '%032x' % number
            key_hash = hashlib.sha256(token.encode()).hexdigest()
            body = json.dumps({'status': 'closed', 'closed_at': 1, 'detail': number},
                              sort_keys=True, separators=(',', ':')).encode()
            hashes[key_hash] = hashlib.sha256(body).hexdigest()
        self.baseline.write_text(json.dumps({'schema': 1, 'ok': True,
            'checked_at': '2026-11-01T03:54:27.995320+00:00', 'closed_phone_batches': 22,
            'phone_history': hashes}))
        self.baseline.chmod(0o600)
        retained = dict(list(hashes.items())[:6])
        missing = dict(list(hashes.items())[6:])
        self.report = {
            'schema': 1, 'baseline_sha256': hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
            'baseline_phone_batches': 22, 'live_closed_phone_batches': 6,
            'checked_at': '2026-11-09T00:00:00+00:00',
            'unchanged_phone_history': retained, 'modified_phone_history': {},
            'verified_expired_phone_history': {}, 'missing_unexpired_phone_history': {},
            'missing_unknown_phone_history': missing, 'voicemail_dependency_phone_history': {},
            'live_phone_history': retained, 'pending_phone_reconciliation': [],
            'missing_phone_ledger': False, 'safe_to_approve_unknown_loss': True,
        }
        self.settings = {'INSTALL_BOOTSTRAP_DIR': str(self.bootstrap),
                         'RECOVERY_DIR': str(self.recovery), 'STATIC_MUTATION_STARTED': '1'}
        j.update(self.transaction, 'recovery_failed', self.settings)
        location = patch.object(j, '__file__', str(self.bootstrap / 'sls_install_transaction.py'))
        location.start()
        self.addCleanup(location.stop)

    def require_api(self):
        self.assertTrue(callable(getattr(j, 'history_review', None)),
                        'No authenticated, transaction-bound administrator history review exists')

    def review(self):
        self.require_api()
        return j.history_review(self.transaction, self.report)

    def approve(self):
        review = self.review()
        return j.approve_history_loss(self.transaction, self.report,
            review['review_sha256'], 'PBX administrator', 'Backups searched; accept the recorded unknown historical loss')

    def test_exact_22_to_6_review_requires_explicit_bound_approval(self):
        originals = {p: p.read_bytes() for p in self.transaction.rglob('*') if p.is_file()}
        result = self.review()
        self.assertTrue(result['review_required'])
        self.assertEqual(result['summary']['unknown_missing_phone_batches'], 16)
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        for path, body in originals.items():
            self.assertEqual(path.read_bytes(), body)
        receipt = self.approve()
        originals.pop(self.transaction / 'transaction.json')
        self.assertEqual(receipt['classification'], 'administrator_accepted_unverified_history_loss')
        self.assertFalse(receipt['missing_history_verified_expired'])
        approved = j.load_history_loss_approval(self.transaction / 'history-loss-approval.json',
                                               self.baseline, self.report)
        self.assertEqual(approved, self.report['missing_unknown_phone_history'])
        self.assertEqual(len(approved), 16)
        for path, body in originals.items():
            self.assertEqual(path.read_bytes(), body)

    def test_wrong_confirmation_or_changed_missing_set_never_creates_receipt(self):
        review = self.review()
        with self.assertRaises(j.TransactionError):
            j.approve_history_loss(self.transaction, self.report, '0' * 64, 'operator', 'Reason given')
        changed = deepcopy(self.report)
        key, value = changed['missing_unknown_phone_history'].popitem()
        changed['unchanged_phone_history'][key] = value
        changed['live_phone_history'][key] = value
        changed['live_closed_phone_batches'] = 7
        with self.assertRaises(j.TransactionError):
            j.approve_history_loss(self.transaction, changed, review['review_sha256'], 'operator', 'Reason given')
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())

    def test_modified_unexpired_voicemail_pending_or_missing_ledger_are_not_waived(self):
        self.require_api()
        for blocker in ('modified', 'unexpired', 'voicemail', 'pending', 'ledger'):
            with self.subTest(blocker=blocker):
                report = deepcopy(self.report)
                if blocker == 'modified':
                    key, digest = report['unchanged_phone_history'].popitem()
                    report['live_phone_history'][key] = 'f' * 64
                    report['modified_phone_history'][key] = {'expected_sha256': digest, 'observed_sha256': 'f' * 64}
                elif blocker in ('unexpired', 'voicemail'):
                    key, digest = report['missing_unknown_phone_history'].popitem()
                    destination = 'missing_unexpired_phone_history' if blocker == 'unexpired' else 'voicemail_dependency_phone_history'
                    report[destination][key] = digest
                elif blocker == 'pending':
                    report['pending_phone_reconciliation'] = ['a' * 64]
                else:
                    report['missing_phone_ledger'] = True
                # A forged true safe flag must not bypass real blocker facts.
                with self.assertRaises(j.TransactionError):
                    j.history_review(self.transaction, report)
                self.assertFalse((self.transaction / 'history-loss-approval.json').exists())

    def test_review_and_receipt_are_stable_across_clock_and_heartbeat_changes(self):
        result = self.review()
        path = self.transaction / 'history-loss-review.json'
        original = path.read_bytes()
        self.report['checked_at'] = '2026-11-10T00:00:00+00:00'
        again = self.review()
        self.assertEqual(again['review_sha256'], result['review_sha256'])
        self.assertEqual(path.read_bytes(), original)
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        old = receipt.read_bytes()
        self.approve()
        self.assertEqual(receipt.read_bytes(), old)

    def test_unrelated_baseline_and_tampered_original_artifacts_reject_receipt(self):
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        unrelated = self.base / 'unrelated-baseline.json'
        unrelated.write_bytes(self.baseline.read_bytes())
        unrelated.chmod(0o600)
        with self.assertRaises(j.TransactionError):
            j.load_history_loss_approval(receipt, unrelated, self.report)
        package = self.transaction / 'package.tgz'
        package.write_bytes(b'not the signed original')
        with self.assertRaises(j.TransactionError):
            j.load_history_loss_approval(receipt, self.baseline, self.report)

    def test_unsafe_or_modified_receipt_never_permits_evidence_cleanup(self):
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        before = receipt.read_bytes()
        receipt.chmod(0o640)
        with self.assertRaises(j.TransactionError):
            j.preserve_completed_evidence(j.state(self.transaction))
        receipt.chmod(0o600)
        value = json.loads(before)
        value['approved_unknown_phone_history'].popitem()
        receipt.write_text(json.dumps(value))
        with self.assertRaises(j.TransactionError):
            j.preserve_completed_evidence(j.state(self.transaction))
        self.assertTrue((self.transaction / 'package.tgz').exists())

    def test_approved_loss_keeps_all_originals_after_rollback_and_later_installations(self):
        self.approve()
        originals = {p: p.read_bytes() for p in self.transaction.rglob('*') if p.is_file()}
        # Receipt is durable before the shell records its completion. A crash in
        # this window must already forbid cleanup.
        self.assertTrue(j.preserve_completed_evidence(j.state(self.transaction)))
        j.update(self.transaction, 'rolled_back', self.settings)
        originals.pop(self.transaction / 'transaction.json')
        for number in range(23):
            current = j.begin(self.root)
            j.update(current, 'abandoned', {})
        self.assertTrue(self.transaction.exists())
        self.assertEqual(j.state(self.transaction)['phase'], 'rolled_back')
        for path, body in originals.items():
            self.assertEqual(path.read_bytes(), body)
        final = j.state(self.transaction)
        self.assertEqual(final['history_loss']['classification'], 'administrator_accepted_unverified_history_loss')
        self.assertEqual(final['history_loss']['accepted_missing_phone_batches'], 16)

    def test_unapproved_review_does_not_grant_loss_permission(self):
        self.review()
        with self.assertRaises((j.TransactionError, OSError)):
            j.load_history_loss_approval(self.transaction / 'history-loss-approval.json',
                                         self.baseline, self.report)
        self.assertFalse(j.preserve_completed_evidence(j.state(self.transaction)))

    def test_malformed_reports_and_unbounded_administrator_text_do_not_grant_approval(self):
        review = self.review()
        for operator, reason in (('', 'Reason'), ('operator\nforged', 'Reason'),
                                 ('x' * 257, 'Reason'), ('operator', ''),
                                 ('operator', 'x' * 2049), ('operator', 'reason\x00tail')):
            with self.subTest(operator=operator, reason=reason[:20]):
                with self.assertRaises(j.TransactionError):
                    j.approve_history_loss(self.transaction, self.report, review['review_sha256'], operator, reason)
                self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        for report in ([], None, {}, {**self.report, 'baseline_sha256': 'f' * 64},
                       {**self.report, 'baseline_phone_batches': True}):
            with self.subTest(report=report):
                with self.assertRaises(j.TransactionError):
                    j.history_review(self.transaction, report)

    def idle_fixture(self):
        spec = importlib.util.spec_from_file_location('approved_loss_idle', self.bootstrap / 'sls_install_idle.py')
        idle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(idle)
        data = self.base / 'data'
        data.mkdir(mode=0o750)
        module = self.base / 'module/module.xml'
        module.parent.mkdir()
        module.write_bytes(b'<module/>')
        marker = module.with_name('PhoneEventService.php')
        marker.write_bytes(b'fixture subsystem')
        proc = self.base / 'proc'
        proc.mkdir()
        spools = [self.base / 'outgoing', self.base / 'spool-tmp']
        for spool in spools:
            spool.mkdir()
        self.live_state = {'schema': 1, 'collector': {'generation': 'b' * 32,
            'boot_id': 'fixture-boot', 'heartbeat_tick': 99}, 'batches': {
                '%032x' % number: {'status': 'closed', 'closed_at': 1, 'detail': number}
                for number in range(1, 7)}}
        live = data / 'phone-admission.json'
        live.write_text(json.dumps(self.live_state))
        live.chmod(0o640)
        check = idle.IdleCheck(data, module=module, proc=proc, spools=spools, channels=lambda: '',
            boot_id='fixture-boot', monotonic=lambda: 100, clock=lambda: 1000000,
            subsystem_paths=(marker, self.base / 'absent-unit', self.base / 'absent-runtime'))
        return idle, check, live

    def test_real_idle_verification_separates_16_accepted_losses_from_verified_expiry(self):
        self.require_api()
        idle, check, live = self.idle_fixture()
        self.report = check.review_history(self.baseline)
        before = {path: path.read_bytes() for path in (self.baseline, live)}
        self.approve()
        result = check.inspect(self.baseline, history_loss_approval=self.transaction / 'history-loss-approval.json')
        self.assertTrue(result['ok'])
        self.assertEqual(result['closed_phone_batches'], 6)
        self.assertEqual(result['accepted_missing_phone_batches'], 16)
        self.assertEqual(result['retired_phone_batches'], 0)
        for path, body in before.items():
            self.assertEqual(path.read_bytes(), body)

    def test_real_idle_approval_still_rejects_modified_new_missing_and_nonexpired_records(self):
        self.require_api()
        idle, check, live = self.idle_fixture()
        self.report = check.review_history(self.baseline)
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        original = deepcopy(self.live_state)
        for fault in ('modified', 'new-missing'):
            with self.subTest(fault=fault):
                self.live_state = deepcopy(original)
                token = next(iter(self.live_state['batches']))
                if fault == 'modified':
                    self.live_state['batches'][token]['detail'] = 'changed'
                else:
                    del self.live_state['batches'][token]
                live.write_text(json.dumps(self.live_state))
                with self.assertRaises(idle.IdleError):
                    check.inspect(self.baseline, history_loss_approval=receipt)
        live.write_text(json.dumps(original))
        proof = self.base / 'complete-backup.json'
        proof.write_text(json.dumps({'schema': 1, 'batches': {
            '%032x' % number: {'status': 'closed', 'closed_at': 1, 'detail': number}
            for number in range(1, 23)}}))
        proof.chmod(0o600)
        check.clock = lambda: 1000
        with self.assertRaises(idle.IdleError):
            check.inspect(self.baseline, history_evidence=proof, history_loss_approval=receipt)

    def test_real_idle_approval_never_waives_an_active_voicemail_dependency(self):
        self.require_api()
        idle, check, live = self.idle_fixture()
        self.report = check.review_history(self.baseline)
        self.approve()
        self.live_state['batches']['f' * 32] = {
            'status': 'active', 'purpose': 'voicemail', 'voicemail': {'source_token': '%032x' % 22}}
        live.write_text(json.dumps(self.live_state))
        with self.assertRaises(idle.IdleError):
            check.inspect(self.baseline, history_loss_approval=self.transaction / 'history-loss-approval.json')

    def shell_preflight(self, mode='', challenge=''):
        idle, check, live = self.idle_fixture()
        launcher = self.base / 'idle-launcher.py'
        launcher.write_text('''import sys
sys.dont_write_bytecode=True
import argparse, importlib.util, json
from pathlib import Path
spec=importlib.util.spec_from_file_location('shell_history_idle',Path(%r)/'sls_install_idle.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
parser=argparse.ArgumentParser();parser.add_argument('--data');parser.add_argument('action')
parser.add_argument('--baseline');parser.add_argument('--repair-collector',action='store_true')
parser.add_argument('--history-evidence');parser.add_argument('--history-loss-approval')
args=parser.parse_args();base=Path(%r)
check=module.IdleCheck(base/'data',module=base/'module/module.xml',proc=base/'proc',
spools=(base/'outgoing',base/'spool-tmp'),channels=lambda:'',boot_id='fixture-boot',
monotonic=lambda:100,clock=lambda:1000000,subsystem_paths=(base/'module/PhoneEventService.php',))
result=check.review_history(args.baseline,history_evidence=args.history_evidence,repair_collector=args.repair_collector)
print(json.dumps(result))
''' % (str(self.bootstrap), str(self.base)))
        launcher.chmod(0o700)
        harness = r'''
source "$1"
fixture="$2"; transaction="$3"; mode="$4"; challenge="$5"
IDLE_TOOL="$fixture/idle-launcher.py"
TRANSACTION_TOOL="$transaction/bootstrap/sls_install_transaction.py"
INSTALL_TRANSACTION_ROOT="$fixture/journal"; INSTALL_TRANSACTION_DIR="$transaction"
RECOVERY_DIR="$transaction/sls-mass-notify-recovery.ABC123"; DATA_DIR="$fixture/data"
INSTALL_NOTIFICATION_SIDE_EFFECTS=0
REQUESTED_HISTORY_REVIEW=0; REQUESTED_HISTORY_LOSS_APPROVAL=""
REQUESTED_HISTORY_LOSS_OPERATOR=""; REQUESTED_HISTORY_LOSS_REASON=""
if [ "$mode" = review ]; then REQUESTED_HISTORY_REVIEW=1; fi
if [ "$mode" = approve ]; then
 REQUESTED_HISTORY_LOSS_APPROVAL="$challenge"
 REQUESTED_HISTORY_LOSS_OPERATOR='PBX administrator'
 REQUESTED_HISTORY_LOSS_REASON='Backups searched; accept the recorded unknown historical loss'
fi
log() { printf '%s\n' "$*" >&2; }
preflight_recovery_history
'''
        return subprocess.run(['bash', '-c', harness, 'fixture', str(ROOT / 'tools/install_release.sh'),
            str(self.base), str(self.transaction), mode, challenge], capture_output=True, text=True, timeout=15)

    def test_shell_preflight_defaults_to_administrator_review_without_restoring(self):
        result = self.shell_preflight()
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertTrue((self.transaction / 'history-loss-review.json').exists())
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        self.assertEqual(j.state(self.transaction)['phase'], 'recovery_failed')
        self.assertTrue((self.transaction / 'package.tgz').exists())

    def test_shell_report_only_returns_success_without_granting_loss_permission(self):
        result = self.shell_preflight('review')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.transaction / 'history-loss-review.json').exists())
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        self.assertEqual(j.state(self.transaction)['phase'], 'recovery_failed')

    def test_shell_explicit_approval_passes_only_the_exact_existing_review(self):
        review = self.review()
        receipt = self.transaction / 'history-loss-approval.json'
        result = self.shell_preflight('approve', review['review_sha256'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(receipt.exists())
        self.assertEqual(json.loads(receipt.read_text())['classification'],
                         'administrator_accepted_unverified_history_loss')

    def test_shell_verified_rollback_keeps_original_accepted_loss_evidence(self):
        self.shell_verified_rollback(True)

    def test_shell_manual_recovery_keeps_originals_without_a_history_loss_exception(self):
        self.shell_verified_rollback(False)

    def shell_verified_rollback(self, with_loss_approval):
        if with_loss_approval:
            self.approve()
        module_backup = self.base / 'previous-module'
        module_backup.mkdir(mode=0o700)
        (module_backup / 'original.php').write_bytes(b'approved previous module')
        approval = self.transaction / 'approval'
        approval.mkdir(mode=0o700)
        (approval / 'original-approval.json').write_bytes(b'original authenticated inventory')
        stage = self.base / 'stage'
        stage.mkdir(mode=0o700)
        (stage / 'original-payload').write_bytes(b'original staging evidence')
        snapshot = self.transaction / 'config.snapshot'
        snapshot.write_bytes(b'original configuration evidence')
        snapshot.chmod(0o600)
        originals = {p: p.read_bytes() for p in self.transaction.rglob('*')
                     if p.is_file() and p.name != 'transaction.json'}
        harness = r'''
source "$1"
fixture="$2"; transaction="$3"
INSTALL_NOTIFICATION_SIDE_EFFECTS=0; RECOVERY_REQUEST_MODE=1
INSTALL_TRANSACTION_ROOT="$fixture/journal"; INSTALL_TRANSACTION_DIR="$transaction"
INSTALL_BOOTSTRAP_DIR="$transaction/bootstrap"; RECOVERY_PROGRAM_DIR="$transaction/bootstrap"
TRANSACTION_TOOL="$transaction/bootstrap/sls_install_transaction.py"
RECOVERY_DIR="$transaction/sls-mass-notify-recovery.ABC123"
UPGRADE_TRUST_DIR="$transaction/approval"; MODULE_BACKUP_DIR="$fixture/previous-module"
STAGING_DIR="$fixture/stage"; STATIC_MUTATION_STARTED=1
verify_recovery_configuration() { :; }
rollback_module_install() { ROLLBACK_ATTEMPTED=1; ROLLBACK_VERIFIED=1; }
restore_freepbx_chown_permissions() { :; }
clear_install_failure() { :; }
record_install_failure() { printf 'failure\n' >>"$fixture/failure-marker"; }
release_worker_coordination() { :; }
log() { printf '%s\n' "$*" >&2; }
trap guard_config_on_exit EXIT
exit 1
'''
        result = subprocess.run(['bash', '-c', harness, 'fixture', str(ROOT / 'tools/install_release.sh'),
            str(self.base), str(self.transaction)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(j.state(self.transaction)['phase'], 'rolled_back')
        for path, body in originals.items():
            self.assertTrue(path.exists(), 'Accepted loss cleanup removed original evidence: ' + str(path))
            self.assertEqual(path.read_bytes(), body)
        self.assertEqual((module_backup / 'original.php').read_bytes(), b'approved previous module')
        self.assertTrue((stage / 'original-payload').exists())
        self.assertTrue(j.state(self.transaction)['recovery_evidence']['original_evidence_preserved'])

    def test_optional_complete_history_evidence_is_fsynced_before_live_mutation(self):
        registration = self.recovery / 'module-registration.json'
        registration.write_text('{"schema":3}')
        registration.chmod(0o600)
        proof = self.recovery / 'history-evidence.json'
        proof.write_text('{"schema":1,"batches":{}}')
        proof.chmod(0o600)
        original_sync = j.os.fsync
        seen = []
        def failing_sync(fd):
            name = os.readlink('/proc/self/fd/' + str(fd))
            seen.append(name)
            if name == str(proof):
                raise OSError('Fixture history evidence storage synchronization failed')
            return original_sync(fd)
        with patch.object(j.os, 'fsync', side_effect=failing_sync):
            with self.assertRaisesRegex(OSError, 'history evidence storage'):
                j.sync_recovery_inputs(self.transaction, self.recovery)
        self.assertIn(str(proof), seen)
        before = proof.read_bytes()
        j.sync_recovery_inputs(self.transaction, self.recovery)
        self.assertEqual(proof.read_bytes(), before)
        proof.chmod(0o640)
        with self.assertRaises(j.TransactionError):
            j.sync_recovery_inputs(self.transaction, self.recovery)

    def test_missing_publisher_verifier_never_ignores_dangling_established_trust_records(self):
        trust = self.base / 'trust'
        trust.mkdir(mode=0o700)
        source = (ROOT / 'tools/install_release.sh').read_text()
        source = source.replace('/usr/local/bin/sls_mass_notify/sls_release_trust.py', str(self.base / 'absent-verifier.py'))
        source = source.replace('/var/lib/sls-mass-notify-trust', str(trust))
        source = source.replace('MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=',
                                self.public.decode().splitlines()[1])
        installer = self.base / 'recovery-installer.sh'
        installer.write_text(source)
        harness = r'''
source "$1"
fixture="$2"
INSTALL_TRANSACTION_ROOT="$2/journal"
acquire_update_coordination() { :; }
acquire_maintenance_coordination() { :; }
prepare_recovery_carrier() { printf 'reached unauthorized factory fallback' >"$fixture/factory-fallback-marker"; return 1; }
recover_interrupted_installation "$3"
'''
        for name in ('publisher-trust.json', 'release-trust.initialized'):
            with self.subTest(record=name):
                target = trust / name
                target.symlink_to(trust / 'missing-original')
                result = subprocess.run(['bash', '-c', harness, 'fixture', str(installer),
                    str(self.base), str(self.transaction)], capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Restore the protected publisher verifier', result.stderr)
                self.assertFalse((self.base / 'factory-fallback-marker').exists())
                self.assertTrue(target.is_symlink())
                target.unlink()

    def test_publisher_expiry_blocks_active_approval_but_cannot_delete_completed_evidence(self):
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        j.update(self.transaction, 'rolled_back', self.settings)
        original = {path: path.read_bytes() for path in self.transaction.rglob('*') if path.is_file()}
        with patch.object(j.time, 'time', return_value=self.now + 7200):
            with self.assertRaisesRegex(ValueError, 'expired'):
                j.load_history_loss_approval(receipt, self.baseline, self.report)
            current = j.begin(self.root)
            self.assertEqual(j.state(current)['phase'], 'preparing')
        for path, body in original.items():
            self.assertEqual(path.read_bytes(), body)

    def test_publisher_revocation_blocks_active_approval_but_preserves_passive_archives(self):
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        j.update(self.transaction, 'rolled_back', self.settings)
        spec = importlib.util.spec_from_file_location('revoked_history_publisher', self.bootstrap / 'sls_release_trust.py')
        publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(publisher)
        store = publisher.TrustStore(self.base / 'unused-policy', self.public)
        policy = store.initialize()
        policy['policy']['keys'][0]['revoked_at'] = self.now - 1
        policy['retired_ids'] = [self.publisher_id]
        store._write(store.state, publisher.canonical(policy))
        original = {path: path.read_bytes() for path in self.transaction.rglob('*') if path.is_file()}
        with self.assertRaisesRegex(ValueError, 'revoked'):
            j.load_history_loss_approval(receipt, self.baseline, self.report)
        current = j.begin(self.root)
        self.assertEqual(j.state(current)['phase'], 'preparing')
        for path, body in original.items():
            self.assertEqual(path.read_bytes(), body)

    def test_genuine_later_backup_can_only_narrow_an_existing_unknown_loss_acceptance(self):
        self.require_api()
        idle, check, live = self.idle_fixture()
        self.report = check.review_history(self.baseline)
        self.approve()
        receipt = self.transaction / 'history-loss-approval.json'
        receipt_before = receipt.read_bytes()
        original = {path: path.read_bytes() for path in (self.baseline, live)}
        for end, expected_retired, expected_accepted in ((15, 8, 8), (23, 16, 0)):
            with self.subTest(proven_expired=expected_retired):
                proof = self.base / ('genuine-backup-' + str(end) + '.json')
                proof.write_text(json.dumps({'schema': 1, 'batches': {
                    '%032x' % number: {'status': 'closed', 'closed_at': 1, 'detail': number}
                    for number in range(7, end)}}))
                proof.chmod(0o600)
                proof_before = proof.read_bytes()
                result = check.inspect(self.baseline, history_evidence=proof, history_loss_approval=receipt)
                self.assertTrue(result['ok'])
                self.assertEqual(result['retired_phone_batches'], expected_retired)
                self.assertEqual(result['accepted_missing_phone_batches'], expected_accepted)
                self.assertEqual(proof.read_bytes(), proof_before)
        self.assertEqual(receipt.read_bytes(), receipt_before)
        self.assertEqual(j.state(self.transaction)['history_loss']['accepted_missing_phone_batches'], 16)
        for path, body in original.items():
            self.assertEqual(path.read_bytes(), body)

    def test_reappearance_of_an_accepted_missing_record_is_not_treated_as_proven_expiry(self):
        self.require_api()
        idle, check, live = self.idle_fixture()
        self.report = check.review_history(self.baseline)
        self.approve()
        self.live_state['batches']['%032x' % 22] = {'status': 'closed', 'closed_at': 1, 'detail': 22}
        live.write_text(json.dumps(self.live_state))
        with self.assertRaises(idle.IdleError):
            check.inspect(self.baseline, history_loss_approval=self.transaction / 'history-loss-approval.json')

    def test_no_loss_review_defers_independently_idle_orphan_until_strict_reconciliation(self):
        idle, check, live = self.idle_fixture()
        self.live_state['batches'] = {'%032x' % number: {
            'status': 'closed', 'closed_at': 1, 'detail': number} for number in range(1, 23)}
        orphan = 'f' * 32
        self.live_state['batches'][orphan] = {'status': 'reserved', 'created_at': 2}
        live.write_text(json.dumps(self.live_state))
        report = check.review_history(self.baseline, repair_collector=True)
        self.assertEqual(len(report['unchanged_phone_history']), 22)
        self.assertEqual(report['missing_unknown_phone_history'], {})
        self.assertEqual(report['pending_phone_reconciliation'], [hashlib.sha256(orphan.encode()).hexdigest()])
        result = j.history_review(self.transaction, report)
        self.assertFalse(result['review_required'])
        self.assertTrue(result['recovery_verification_deferred'])
        self.assertEqual(result['pending_phone_reconciliation'], report['pending_phone_reconciliation'])
        self.assertFalse((self.transaction / 'history-loss-review.json').exists())
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        with self.assertRaises(j.TransactionError):
            j.approve_history_loss(self.transaction, report, '0' * 64, 'operator', 'Cannot waive reconciliation')
        with self.assertRaises(idle.IdleError):
            check.inspect(self.baseline)
        self.live_state['batches'][orphan].update(status='closed', closed_at=2)
        live.write_text(json.dumps(self.live_state))
        self.assertTrue(check.inspect(self.baseline)['ok'])

    def test_fresh_no_loss_review_defers_missing_candidate_ledger_until_absence_is_restored(self):
        idle, check, live = self.idle_fixture()
        self.baseline.write_text(json.dumps({'schema': 1, 'ok': True, 'installed': False,
            'closed_phone_batches': 0, 'phone_history': {}, 'pending_phone_reconciliation': []}))
        live.unlink()
        report = check.review_history(self.baseline, repair_collector=True)
        self.assertEqual(report['baseline_phone_batches'], 0)
        self.assertTrue(report['missing_phone_ledger'])
        self.assertEqual(report['missing_unknown_phone_history'], {})
        result = j.history_review(self.transaction, report)
        self.assertFalse(result['review_required'])
        self.assertTrue(result['recovery_verification_deferred'])
        self.assertTrue(result['missing_phone_ledger'])
        self.assertFalse((self.transaction / 'history-loss-review.json').exists())
        self.assertFalse((self.transaction / 'history-loss-approval.json').exists())
        with self.assertRaises(j.TransactionError):
            j.approve_history_loss(self.transaction, report, '0' * 64, 'operator', 'Cannot waive ledger verification')
        with self.assertRaises(idle.IdleError):
            check.inspect(self.baseline)
        # A fresh-install rollback removes candidate module markers. Original
        # absence can then pass strict final verification without inventing a ledger.
        check.module.unlink()
        for marker in check.subsystem_paths:
            marker.unlink(missing_ok=True)
        self.assertTrue(check.inspect(self.baseline)['ok'])

    def test_manual_recovery_retention_keeps_all_originals_across_later_generation_pruning(self):
        self.assertTrue(callable(getattr(j, 'retain_recovery_evidence', None)),
                        'Manual recovery has no durable evidence-retention marker')
        originals = {path: path.read_bytes() for path in self.transaction.rglob('*')
                     if path.is_file() and path.name != 'transaction.json'}
        j.update(self.transaction, 'rolled_back', self.settings)
        marker = j.retain_recovery_evidence(self.transaction)
        self.assertTrue(marker['original_evidence_preserved'])
        self.assertEqual(marker['schema'], 1)
        self.assertTrue(j.preserve_completed_evidence(j.state(self.transaction)))
        for number in range(23):
            current = j.begin(self.root)
            j.update(current, 'abandoned', {})
        for path, body in originals.items():
            self.assertEqual(path.read_bytes(), body)
        self.assertTrue(j.state(self.transaction)['recovery_evidence']['original_evidence_preserved'])

    def test_manual_retention_also_handles_recovered_preparation_without_history_snapshot(self):
        self.assertTrue(callable(getattr(j, 'retain_recovery_evidence', None)),
                        'Manual recovery has no durable evidence-retention marker')
        self.settings['RECOVERY_DIR'] = ''
        j.update(self.transaction, 'rolled_back', self.settings)
        marker = j.retain_recovery_evidence(self.transaction)
        self.assertTrue(marker['original_evidence_preserved'])
        self.assertEqual(marker['original_artifacts']['package_sha256'],
                         json.loads(self.manifest.read_text())['package_sha256'])
        j.begin(self.root)
        self.assertTrue((self.transaction / 'package.tgz').exists())

    def test_manual_retention_authenticates_once_then_survives_publisher_expiry(self):
        self.assertTrue(callable(getattr(j, 'retain_recovery_evidence', None)),
                        'Manual recovery has no durable evidence-retention marker')
        with self.assertRaises(j.TransactionError):
            j.retain_recovery_evidence(self.transaction)
        j.update(self.transaction, 'rolled_back', self.settings)
        marker = j.retain_recovery_evidence(self.transaction)
        with patch.object(j.time, 'time', return_value=self.now + 7200):
            self.assertTrue(j.preserve_completed_evidence(j.state(self.transaction)))
            j.begin(self.root)
        self.assertEqual(j.state(self.transaction)['recovery_evidence'], marker)
        (self.transaction / 'package.tgz').write_bytes(b'changed forensic artifact')
        with self.assertRaises(j.TransactionError):
            j.preserve_completed_evidence(j.state(self.transaction))

    def test_manual_rollback_and_retention_marker_publish_in_one_journal_replacement(self):
        original_replace = j.os.replace
        replacements = []
        def inspect_replace(source, destination, *args, **kwargs):
            if destination == 'transaction.json':
                folder = Path(os.readlink('/proc/self/fd/' + str(kwargs['src_dir_fd'])))
                replacements.append(json.loads((folder / source).read_text()))
            return original_replace(source, destination, *args, **kwargs)
        with patch.object(j.os, 'replace', side_effect=inspect_replace):
            j.update(self.transaction, 'rolled_back', self.settings, preserve_recovery_evidence=True)
        self.assertEqual(len(replacements), 1)
        self.assertEqual(replacements[0]['phase'], 'rolled_back')
        self.assertTrue(replacements[0]['recovery_evidence']['original_evidence_preserved'])
        j.begin(self.root)
        self.assertTrue((self.transaction / 'package.tgz').exists())

    def test_failed_atomic_manual_completion_never_exposes_unprotected_terminal_state(self):
        for moment in ('before-replace', 'after-replace'):
            with self.subTest(moment=moment):
                # A previous successful case is not reused: each fault sees a
                # genuinely unfinished transaction with its original artifacts.
                original_replace = j.os.replace
                original_sync = j.os.fsync
                def replace(source, destination, *args, **kwargs):
                    if destination == 'transaction.json' and moment == 'before-replace':
                        raise OSError('Fixture refused journal replacement')
                    return original_replace(source, destination, *args, **kwargs)
                def sync(fd):
                    if moment == 'after-replace' and os.path.isdir('/proc/self/fd/' + str(fd)) \
                            and j.state(self.transaction)['phase'] == 'rolled_back':
                        raise OSError('Fixture refused directory synchronization')
                    return original_sync(fd)
                with patch.object(j.os, 'replace', side_effect=replace), patch.object(j.os, 'fsync', side_effect=sync):
                    with self.assertRaisesRegex(OSError, 'Fixture refused'):
                        j.update(self.transaction, 'rolled_back', self.settings, preserve_recovery_evidence=True)
                value = j.state(self.transaction)
                if moment == 'before-replace':
                    self.assertEqual(value['phase'], 'recovery_failed')
                    with self.assertRaises(j.TransactionError):
                        j.begin(self.root)
                else:
                    self.assertEqual(value['phase'], 'rolled_back')
                    self.assertTrue(value['recovery_evidence']['original_evidence_preserved'])
                    j.begin(self.root)
                self.assertTrue((self.transaction / 'package.tgz').exists())

    def test_transaction_cli_can_atomically_retain_only_manual_rollback_completion(self):
        command = ['python3', '-I', str(self.bootstrap / 'sls_install_transaction.py'),
                   '--root', str(self.root), '--transaction', str(self.transaction),
                   '--preserve-recovery-evidence']
        refused = subprocess.run([*command, '--phase', 'committed', 'update'], input=json.dumps(self.settings),
                                 text=True, capture_output=True, timeout=15)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(j.state(self.transaction)['phase'], 'recovery_failed')
        result = subprocess.run([*command, '--phase', 'rolled_back', 'update'], input=json.dumps(self.settings),
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(j.state(self.transaction)['recovery_evidence']['original_evidence_preserved'])
        j.begin(self.root)
        self.assertTrue((self.transaction / 'package.tgz').exists())


if __name__ == '__main__':
    unittest.main()
