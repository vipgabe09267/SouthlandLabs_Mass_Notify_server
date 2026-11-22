#!/usr/bin/python3
"""Authenticated installer entry points for first-upgrade retained-source review."""
import hashlib
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Use the private isolated test runner; no installer was executed.')
ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
spec = importlib.util.spec_from_file_location('retained_entry_fixtures', ROOT / 'tools/test_publisher_authority_continuity.py')
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
HELPERS = ('sls_module_trust sls_release_trust sls_privileged_install sls_installer_recovery '
           'sls_install_transaction sls_install_idle sls_install_guard sls_audio_state sls_config_crypto '
           'sls_upgrade_trust sls_legacy_permissions').split()


class RetainedInstallerEntry(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.PublisherAuthorityContinuity(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        # The isolated runner hides /run. Model Debian's existing canonical
        # lock directory without touching any host lock or service.
        Path('/run/lock').mkdir(mode=0o755, exist_ok=True)
        f = self.fixture
        f.overlap()
        prior = f.release(1, version='0.1.9-beta', expires_at=f.now - 60)
        with patch('time.time', return_value=f.now - 120):
            f.module.enroll_sls(f.directory, *prior)
        self.base = f.root
        self.assets = self.base / 'current-assets'; self.assets.mkdir(mode=0o700)
        self.scratch = self.base / 'scratch'; self.scratch.mkdir(mode=0o700)
        self.unexpected = self.base / 'unexpected-installation-action'
        self.executed = self.base / 'authenticated-helper-executed'
        (self.base / 'freepbx.conf').write_text('inert native bootstrap sentinel')
        framework = self.base / 'framework'; framework.mkdir()
        (framework / 'module.xml').write_text('<module/>')
        # The trusted installed verifier is old enough not to provide the new
        # CLI, but it still enforces the existing current publisher policy.
        publisher_path = f.helpers / 'sls_release_trust.py'
        publisher_path.write_text(publisher_path.read_text().replace("Path('/var/lib/sls-mass-notify-trust')", repr_path(f.directory)))
        self.installer = self.assets / 'install_release.sh'
        source = (ROOT / 'tools/install_release.sh').read_text()
        source = source.replace('/etc/freepbx.conf', str(self.base / 'freepbx.conf'))
        source = source.replace('/var/www/html/admin/modules/framework', str(framework))
        source = source.replace('/usr/local/bin/sls_mass_notify', str(f.helpers))
        source = source.replace('/var/lib/sls-mass-notify-trust', str(f.directory))
        source, count = re.subn(r'^public_key = .*$', lambda _: 'public_key = ' + repr(f.keys[0][1]), source, flags=re.M)
        self.assertEqual(count, 1)
        adapters = r'''
fixture_unexpected() { printf '%s\n' "$1" >>"$SLS_FIXTURE_UNEXPECTED"; return 97; }
bootstrap_resource_capacity() {
  if [ -n "${SLS_FIXTURE_RESOURCE_REPORT:-}" ]; then
    printf '%s\n' "$SLS_FIXTURE_RESOURCE_REPORT"
    return "${SLS_FIXTURE_RESOURCE_STATUS:-0}"
  fi
  printf '%s\n' '{"requirements":{},"deployment_profile":"standard","profile_selection":{"standard_memory_eligible":true,"lite_memory_eligible":false}}'
}
select_install_temp_root() { INSTALL_TEMP_ROOT="$SLS_FIXTURE_SCRATCH"; }
fetch_release_asset() {
  case "$1" in
    */release-manifest.json) cp "$SLS_FIXTURE_ASSETS/release-manifest.json" "$2" ;;
    */release-manifest.sig) cp "$SLS_FIXTURE_ASSETS/release-manifest.sig" "$2" ;;
    */slsmassnotifyserver-0.2.0-beta.tgz) cp "$SLS_FIXTURE_ASSETS/slsmassnotifyserver-0.2.0-beta.tgz" "$2" ;;
    *) return 98 ;;
  esac
}
module_registry_state() { fixture_unexpected module_registry_state; }
prepare_authenticated_installer() {
  if [ "${SLS_FIXTURE_INSPECT_ONLY:-0}" = 1 ]; then return 0; fi
  fixture_unexpected prepare_authenticated_installer
}
ensure_installer_log_prerequisites() { fixture_unexpected normal_install; }
begin_install_transaction() { fixture_unexpected begin_install_transaction; }
acquire_update_coordination() { fixture_unexpected acquire_update_coordination; }
acquire_maintenance_coordination() { fixture_unexpected acquire_maintenance_coordination; }
'''
        marker = 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then\n  main "$@"\nfi'
        self.assertEqual(source.count(marker), 1)
        source = source.replace(marker, adapters + '\n' + marker)
        self.installer.write_text(source)
        self.archive = self.assets / 'slsmassnotifyserver-0.2.0-beta.tgz'
        files = {'module.xml': b'<module><rawname>slsmassnotifyserver</rawname><version>0.2.0-beta</version></module>'}
        for name in HELPERS:
            path = f.helpers / (name + '.py')
            body = path.read_bytes() if path.exists() else (BIN / (name + '.py')).read_bytes()
            if name == 'sls_upgrade_trust':
                # Observe execution without replacing any authentication/review
                # behavior. This observation is covered by the signed fixture.
                body = body.replace(b"if __name__ == '__main__':", b"if __name__ == '__main__':\n    Path(os.environ['SLS_FIXTURE_EXECUTED']).write_text('verified new helper')")
            files['bin/sls_mass_notify/' + name + '.py'] = body
        files['bin/sls_mass_notify/freepbx-mirror-signing.pub'] = (BIN / 'freepbx-mirror-signing.pub').read_bytes()
        with tarfile.open(self.archive, 'w:gz') as stream:
            for name, body in files.items():
                entry = tarfile.TarInfo('slsmassnotifyserver/' + name)
                entry.size = len(body); entry.mode = 0o644
                stream.addfile(entry, io.BytesIO(body))
        self.manifest = {'schema': 1, 'version': '0.2.0-beta', 'tag': 'v0.2.0-beta',
            'package': self.archive.name, 'package_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            'installer_sha256': hashlib.sha256(self.installer.read_bytes()).hexdigest(),
            'signing': {'key_id': f.publisher.key_entry(f.keys[0][1])['id'],
                        'issued_at': f.now - 1, 'expires_at': f.now + 3600}}
        self.sign()
        self.bootstrap = self.base / 'bootstrap.sh'
        bootstrap = (ROOT / 'tools/install_bootstrap.sh').read_text().replace('/var/lib/sls-mass-notify-trust', str(f.directory))
        bootstrap = bootstrap.replace('/usr/local/bin/sls_mass_notify', str(f.helpers))
        original = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=\n-----END PUBLIC KEY-----'
        self.assertEqual(bootstrap.count(original), 1)
        self.bootstrap.write_text(bootstrap.replace(original, f.keys[0][1].decode().strip()))
        self.environment = dict(os.environ, SLS_FIXTURE_UNEXPECTED=str(self.unexpected),
            SLS_FIXTURE_SCRATCH=str(self.scratch), SLS_FIXTURE_EXECUTED=str(self.executed),
            SLS_FIXTURE_ASSETS=str(self.assets), SLS_MASS_NOTIFY_TGZ=str(self.archive),
            SLS_MASS_NOTIFY_SHA256=self.manifest['package_sha256'],
            SLS_MASS_NOTIFY_MANIFEST=str(self.assets / 'release-manifest.json'),
            SLS_MASS_NOTIFY_MANIFEST_SIGNATURE=str(self.assets / 'release-manifest.sig'))
        self.environment.pop('SLS_MASS_NOTIFY_TGZ_URL', None)

    def sign(self):
        f = self.fixture
        body = f.publisher.canonical(self.manifest)
        (self.assets / 'release-manifest.json').write_bytes(body)
        (self.assets / 'release-manifest.sig').write_bytes(f.sign(body, 0))

    def invoke(self, arguments, *, bootstrap=False, inspect_only=False):
        environment = dict(self.environment, SLS_FIXTURE_INSPECT_ONLY='1' if inspect_only else '0')
        if bootstrap:
            command = r'''source "$1"
bootstrap_download() { cp "$SLS_FIXTURE_ASSETS/install_release.sh" "$SLS_FIXTURE_ASSETS/release-manifest.json" "$SLS_FIXTURE_ASSETS/release-manifest.sig" "$1/"; }
shift
bootstrap_main "$@"
'''
            argv = ['/bin/bash', '-c', command, 'fixture', str(self.bootstrap), '0.2.0-beta', *arguments]
        else:
            argv = ['/bin/bash', str(self.installer), *arguments]
        return subprocess.run(argv, env=environment, text=True, capture_output=True, timeout=25)

    def review(self, bootstrap=False):
        result = self.invoke(['--upgrade', '--review-retained'] if bootstrap else ['--review-retained'], bootstrap=bootstrap)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = []
        for line in result.stdout.splitlines():
            try: value = json.loads(line)
            except ValueError: continue
            if isinstance(value, dict) and 'challenge' in value: rows.append(value)
        self.assertEqual(len(rows), 1, result.stdout)
        self.assertTrue(self.executed.exists(), 'The actual authenticated new helper was not executed')
        return rows[0]

    def assert_no_install(self):
        self.assertFalse(self.unexpected.exists(), self.unexpected.read_text() if self.unexpected.exists() else '')
        self.assertEqual((self.base / 'freepbx.conf').read_text(), 'inert native bootstrap sentinel')
        self.assertEqual(list(self.scratch.glob('sls-mass-notify-download.*')), [])
        self.assertEqual(list(self.scratch.glob('sls-mass-notify-stage.*')), [])
        self.assertEqual(list(self.scratch.glob('sls-mass-notify-bootstrap.*')), [])

    def test_actual_installer_reviews_signed_new_helper_without_normal_preparation(self):
        before = {str(path.relative_to(self.fixture.directory)): path.read_bytes()
                  for path in self.fixture.directory.rglob('*') if path.is_file()}
        reviewed = self.review()
        self.assertRegex(reviewed['challenge'], r'^[a-f0-9]{64}$')
        self.assertEqual(before, {str(path.relative_to(self.fixture.directory)): path.read_bytes()
                         for path in self.fixture.directory.rglob('*') if path.is_file()})
        self.assertFalse((self.fixture.directory / 'retained-release-approval.json').exists())
        self.assert_no_install()

    def test_explicit_approval_preserves_literal_metadata_and_only_adds_bounded_receipt(self):
        reviewed = self.review()
        pointer = (self.fixture.directory / 'slsmassnotifyserver.active.json').read_bytes()
        literal = 'Fixture operator $(touch ' + str(self.base / 'must-not-execute') + ')'
        reason = 'Reviewed this exact retained source; approval is separate from installation.'
        result = self.invoke(['--approve-retained', reviewed['challenge'], '--operator', literal, '--reason', reason])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = self.fixture.directory / 'retained-release-approval.json'
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        saved = json.loads(receipt.read_bytes())
        self.assertEqual(saved['operator'], literal)
        self.assertEqual(saved['reason'], reason)
        self.assertLessEqual(saved['expires_at'] - saved['issued_at'], 7 * 86400)
        self.assertFalse((self.base / 'must-not-execute').exists())
        self.assertEqual((self.fixture.directory / 'slsmassnotifyserver.active.json').read_bytes(), pointer)
        self.assert_no_install()

    def test_bootstrap_upgrade_passes_review_and_approval_through_real_signatures(self):
        reviewed = self.review(bootstrap=True)
        result = self.invoke(['--upgrade', '--approve-retained', reviewed['challenge'], '--operator', 'Fixture administrator',
                              '--reason', 'Independently reviewed the exact protected retained generation.'], bootstrap=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.fixture.directory / 'retained-release-approval.json').is_file())
        self.assert_no_install()

    def test_bad_signature_and_installer_digest_never_execute_downloaded_helper(self):
        for failure in ('signature', 'installer'):
            with self.subTest(failure=failure):
                self.executed.unlink(missing_ok=True)
                self.sign()
                if failure == 'signature':
                    (self.assets / 'release-manifest.sig').write_bytes(b'\0' * 64)
                else:
                    self.manifest['installer_sha256'] = '0' * 64; self.sign()
                result = self.invoke(['--review-retained'])
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.executed.exists())
                self.assertFalse((self.fixture.directory / 'retained-release-approval.json').exists())
                self.assert_no_install()

    def test_wrong_challenge_and_revoked_retained_key_cannot_create_approval(self):
        reviewed = self.review()
        result = self.invoke(['--approve-retained', '0' * 64, '--operator', 'Fixture administrator',
                              '--reason', 'This different challenge must not authorize retained source.'])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.fixture.directory / 'retained-release-approval.json').exists())
        policy = self.fixture.store.load()[0]['policy']; policy['sequence'] += 1
        policy['keys'][1]['revoked_at'] = self.fixture.now
        self.fixture.transition(policy, (0,))
        result = self.invoke(['--approve-retained', reviewed['challenge'], '--operator', 'Fixture administrator',
                              '--reason', 'An old review cannot override the revoked retained signing key.'])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.fixture.directory / 'retained-release-approval.json').exists())
        self.assert_no_install()

    def test_inspection_also_avoids_native_module_registry_bootstrap(self):
        result = self.invoke(['--inspect'], inspect_only=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_install()

    def test_retained_review_does_not_require_lite_profile_conversion_after_ram_upgrade(self):
        self.environment['SLS_FIXTURE_RESOURCE_REPORT'] = json.dumps({'requirements': {}, 'deployment_profile': 'lite',
            'profile_selection': {'standard_memory_eligible': True, 'lite_memory_eligible': True}})
        self.review()
        self.assert_no_install()

    def test_retained_review_does_not_require_installation_cpu_or_ram_capacity(self):
        self.environment['SLS_FIXTURE_RESOURCE_REPORT'] = json.dumps({'requirements': {}, 'deployment_profile': 'standard',
            'profile_selection': {'standard_memory_eligible': False, 'lite_memory_eligible': False},
            'errors': [{'code': 'insufficient_compute', 'message': 'Private low-volume fixture'}]})
        self.environment['SLS_FIXTURE_RESOURCE_STATUS'] = '2'
        self.review()
        self.assert_no_install()

    def test_retained_scratch_report_qualifies_bytes_inodes_and_readonly_before_selection(self):
        source = (ROOT / 'tools/install_release.sh').read_text()
        marker = "<<'PYRETAINEDSCRATCH'\n"
        self.assertTrue(marker in source, 'Retained review needs a purpose-specific bounded scratch probe')
        body = source.split(marker, 1)[1].split('\nPYRETAINEDSCRATCH', 1)[0]
        def execute(rows):
            output = io.StringIO()
            with patch('os.fstatvfs', side_effect=rows), contextlib.redirect_stdout(output):
                try:
                    exec(compile(body, '<actual retained scratch probe>', 'exec'), {})
                except SystemExit as error:
                    return error.code, output.getvalue()
            return 0, output.getvalue()
        required_bytes = 160*1048576 + 5028*4096
        def row(free=required_bytes, inodes=5028, readonly=False):
            return SimpleNamespace(f_bavail=free, f_frsize=1, f_favail=inodes,
                                   f_flag=os.ST_RDONLY if readonly else 0)
        for rejected in (row(free=required_bytes-1), row(inodes=5027), row(readonly=True)):
            with self.subTest(rejected=rejected):
                status, _ = execute([rejected, rejected])
                self.assertNotEqual(status, 0)
        status, text = execute([row()])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(text)['requirements']['storage']['temporary_directory'], '/tmp')
        status, text = execute([row(free=0), row()])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(text)['requirements']['storage']['temporary_directory'], '/var/tmp')

    def test_ordinary_inspection_keeps_installation_resource_and_profile_admission(self):
        for report, status in (({'requirements': {}, 'deployment_profile': 'lite',
                                'profile_selection': {'standard_memory_eligible': True, 'lite_memory_eligible': True}}, '0'),
                               ({'requirements': {}, 'errors': [{'code': 'insufficient_compute'}]}, '2')):
            with self.subTest(status=status):
                self.environment['SLS_FIXTURE_RESOURCE_REPORT'] = json.dumps(report)
                self.environment['SLS_FIXTURE_RESOURCE_STATUS'] = status
                result = self.invoke(['--inspect'], inspect_only=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.executed.exists())
                self.assert_no_install()

    def test_default_package_pin_rejection_cleans_scratch_before_returning(self):
        self.environment.pop('SLS_MASS_NOTIFY_SHA256')
        result = self.invoke(['--review-retained'])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.executed.exists())
        self.assertIn('does not match the current', result.stdout + result.stderr)
        self.assert_no_install()

    def test_empty_download_rejection_cleans_scratch_before_returning(self):
        self.archive.write_bytes(b'')
        result = self.invoke(['--review-retained'])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.executed.exists())
        self.assert_no_install()

    def test_malformed_or_combined_modes_stop_before_authentication_or_native_work(self):
        cases = [
            ['--lite', '--review-retained'], ['--review-retained', '--inspect'],
            ['--recover', '/tmp/not-a-transaction', '--review-retained'],
            ['--approve-retained'], ['--approve-retained', '0' * 64],
            ['--review-retained', '--operator', 'Fixture'],
            ['--approve-retained', '0' * 64, '--operator', 'Fixture', '--operator', 'Duplicate', '--reason', 'Reviewed exact evidence.'],
            ['--approve-retained', '0' * 64, '--operator', 'Fixture', '--reason', 'short'],
            ['--approve-retained', '0' * 64, '--operator', 'Fixture\nInjected', '--reason', 'Reviewed exact evidence.'],
            ['--review-retained', '--unknown'], ['--review-retained', 'one', 'two'],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.executed.exists())
                self.assert_no_install()

    def test_bootstrap_requires_upgrade_and_rejects_mixed_modes(self):
        for arguments in (['--review-retained'], ['--upgrade', '--standard', '--review-retained'],
                          ['--upgrade', '--review-retained', '--inspect'],
                          ['--upgrade', '--approve-retained', '0' * 64, '--operator', 'Fixture']):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments, bootstrap=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.executed.exists())
                self.assert_no_install()


def repr_path(path):
    return 'Path(' + repr(str(path)) + ')'


if __name__ == '__main__':
    unittest.main()
