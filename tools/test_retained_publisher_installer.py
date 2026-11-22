#!/usr/bin/python3
"""Real signed bootstrap-to-package verification after normal runtime removal."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Use the private isolated test runner; no installer was executed.')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('retained_publisher_fixture', ROOT / 'tools/test_retained_installer_entry.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class RetainedPublisherInstaller(unittest.TestCase):
    def setUp(self):
        self.entry = fixtures.RetainedInstallerEntry(methodName='runTest')
        self.entry.setUp()
        self.addCleanup(self.entry.doCleanups)
        self.fixture = f = self.entry.fixture
        # Normal uninstall preserves the already-approved private generation,
        # including its publisher verifier, while removing the installed runtime.
        prior = f.release(1, version='0.1.9-beta', expires_at=f.now - 60, include_helpers=True)
        with patch('time.time', return_value=f.now - 120):
            f.module.enroll_sls(f.directory, *prior)
        _, self.generation = f.module.load(f.directory, 'slsmassnotifyserver')
        self.reference = f.directory / 'slsmassnotifyserver.active.json'
        self.original_reference = self.reference.read_bytes()
        self.original_generation = self.generation
        self.original_inventory = (self.generation / 'inventory.json').read_bytes()
        self.retained = self.generation / 'module/bin/sls_mass_notify/sls_release_trust.py'
        self.injected = self.entry.base / 'unverified-source-executed'
        shutil.rmtree(f.helpers)

    def sign_candidate(self, number):
        f = self.fixture
        self.entry.manifest['signing']['key_id'] = f.publisher.key_entry(f.keys[number][1])['id']
        body = f.publisher.canonical(self.entry.manifest)
        (self.entry.assets / 'release-manifest.json').write_bytes(body)
        (self.entry.assets / 'release-manifest.sig').write_bytes(f.sign(body, number))

    def invoke(self, *, bootstrap):
        return self.entry.invoke(['--upgrade', '--inspect'] if bootstrap else ['--inspect'],
                                 bootstrap=bootstrap, inspect_only=True)

    def assert_read_only(self):
        self.entry.assert_no_install()
        self.assertFalse(self.entry.executed.exists(), 'A candidate helper main was executed during verification-only inspection')
        self.assertFalse(self.injected.exists(), 'Unauthenticated retained source executed')

    def assert_rejected_at_both_boundaries(self, expected_installer_error=None):
        before = {path.name: path.read_bytes() for path in self.fixture.directory.iterdir() if path.is_file()}
        for bootstrap in (True, False):
            with self.subTest(bootstrap=bootstrap):
                result = self.invoke(bootstrap=bootstrap)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                if not bootstrap and expected_installer_error:
                    self.assertIn(expected_installer_error, result.stdout + result.stderr)
                self.assert_read_only()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.fixture.directory.iterdir() if path.is_file()})

    def replace_inventory(self, raw):
        # Root-private evidence is immutable in production. These fixtures model
        # independently corrupted approvals, including a matching outer digest,
        # to exercise schema/source/target checks before any helper execution.
        digest = hashlib.sha256(raw).hexdigest()
        destination = self.fixture.directory / ('slsmassnotifyserver-' + digest)
        self.generation.rename(destination)
        self.generation = destination
        (destination / 'inventory.json').write_bytes(raw)
        self.reference.write_bytes(self.fixture.publisher.canonical({'generation': destination.name, 'sha256': digest}))

    def restore_inventory(self):
        self.generation.rename(self.original_generation)
        self.generation = self.original_generation
        (self.generation / 'inventory.json').write_bytes(self.original_inventory)
        self.reference.write_bytes(self.original_reference)

    def test_bootstrap_then_real_package_verifier_accepts_current_A_and_B_after_uninstall(self):
        before = {path.name: path.read_bytes() for path in self.fixture.directory.iterdir() if path.is_file()}
        for number in (0, 1):
            with self.subTest(publisher=number):
                self.sign_candidate(number)
                result = self.invoke(bootstrap=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Publisher signature and installer hash verified for 0.2.0-beta.', result.stdout)
                self.assertIn('Publisher signature and installer/package hashes verified.', result.stdout)
                self.assert_read_only()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.fixture.directory.iterdir() if path.is_file()})
        self.assertFalse(self.fixture.helpers.exists(), 'Inspection recreated the removed runtime')

    def test_missing_retained_verifier_never_uses_candidate_source(self):
        self.retained.unlink()
        self.assert_rejected_at_both_boundaries()

    def test_changed_retained_verifier_is_rejected_before_execution(self):
        self.retained.write_bytes(self.retained.read_bytes() +
            ('\nfrom pathlib import Path\nPath(' + repr(str(self.injected)) + ').write_text("executed")\n').encode())
        self.assert_rejected_at_both_boundaries()

    def test_symlink_hardlink_and_writable_retained_verifiers_are_rejected(self):
        original = self.retained.read_bytes()
        for kind in ('symlink', 'hardlink', 'writable'):
            with self.subTest(kind=kind):
                self.retained.unlink()
                other = self.entry.base / ('unapproved-helper-' + kind)
                other.write_bytes(original); other.chmod(0o600)
                if kind == 'symlink':
                    self.retained.symlink_to(other)
                elif kind == 'hardlink':
                    os.link(other, self.retained)
                else:
                    self.retained.write_bytes(original); self.retained.chmod(0o666)
                self.assert_rejected_at_both_boundaries()
                self.retained.unlink(); self.retained.write_bytes(original); self.retained.chmod(0o600)

    def test_missing_or_changed_inventory_and_reference_refuse(self):
        inventory = self.generation / 'inventory.json'
        for path, original in ((inventory, self.original_inventory), (self.reference, self.original_reference)):
            for kind in ('missing', 'changed'):
                with self.subTest(path=path.name, kind=kind):
                    if kind == 'missing': path.unlink()
                    else: path.write_bytes(b'{}')
                    self.assert_rejected_at_both_boundaries()
                    path.write_bytes(original); path.chmod(0o600)

    def test_inventory_schema_independent_source_and_exact_target_are_required(self):
        relative = 'bin/sls_mass_notify/sls_release_trust.py'
        for failure in ('schema', 'module', 'source', 'archive', 'missing-entry', 'target', 'entry-hash', 'duplicate'):
            with self.subTest(failure=failure):
                inventory = json.loads(self.original_inventory)
                if failure == 'schema': inventory['schema'] = 2
                elif failure == 'module': inventory['module'] = 'framework'
                elif failure == 'source': inventory['source']['kind'] = 'candidate-self-approved'
                elif failure == 'archive': inventory['source']['archive_sha256'] = '../unapproved'
                elif failure == 'missing-entry': del inventory['files'][relative]
                elif failure == 'target': inventory['files'][relative]['target'] = 'admin/modules/framework/' + relative
                elif failure == 'entry-hash': inventory['files'][relative]['sha256'] = '0' * 64
                raw = self.fixture.publisher.canonical(inventory)
                if failure == 'duplicate': raw = b'{"schema":1,' + raw[1:]
                self.replace_inventory(raw)
                self.assert_rejected_at_both_boundaries()
                self.restore_inventory()

    def test_live_revocation_and_missing_policy_override_old_approved_source(self):
        f = self.fixture
        original = f.store.state.read_bytes()
        for number in (0, 1):
            with self.subTest(revoked=number):
                self.sign_candidate(number)
                state = json.loads(original)
                state['policy']['keys'][number]['revoked_at'] = f.now - 1
                state['retired_ids'].append(state['policy']['keys'][number]['id'])
                f.store.state.write_bytes(f.publisher.canonical(state))
                self.assert_rejected_at_both_boundaries()
                f.store.state.write_bytes(original)
        self.sign_candidate(0)
        for path in (f.store.state, f.store.marker):
            with self.subTest(missing=path.name):
                saved = path.read_bytes(); path.unlink()
                self.assert_rejected_at_both_boundaries()
                path.write_bytes(saved); path.chmod(0o600)

    def test_missing_retained_inventory_cannot_reset_initialized_current_policy(self):
        self.reference.unlink()
        self.assert_rejected_at_both_boundaries('Established publisher trust requires its protected verifier')

    def test_malformed_existing_helper_cannot_fall_back_to_valid_retained_source(self):
        self.fixture.helpers.mkdir(mode=0o700)
        installed = self.fixture.helpers / 'sls_release_trust.py'
        installed.symlink_to(self.retained)
        self.assert_rejected_at_both_boundaries('Installed publisher verifier is not protected by root')

    def test_legacy_pre_policy_retained_source_preserves_original_A_only(self):
        self.fixture.store.state.unlink()
        self.fixture.store.marker.unlink()
        self.sign_candidate(0)
        for bootstrap in (True, False):
            with self.subTest(bootstrap=bootstrap):
                result = self.invoke(bootstrap=bootstrap)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Publisher signature and installer/package hashes verified.', result.stdout)
                self.assert_read_only()
        self.sign_candidate(1)
        self.assert_rejected_at_both_boundaries()

    def test_fresh_direct_installer_preserves_pinned_A_only_fallback(self):
        shutil.rmtree(self.fixture.directory)
        self.sign_candidate(0)
        result = self.invoke(bootstrap=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Publisher signature and installer/package hashes verified.', result.stdout)
        self.assert_read_only()
        self.sign_candidate(1)
        result = self.invoke(bootstrap=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_read_only()


if __name__ == '__main__':
    unittest.main()
