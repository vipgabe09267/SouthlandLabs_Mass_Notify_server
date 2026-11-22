#!/usr/bin/python3
"""Behavioral trust regressions for native Framework layouts and interrupted writes.

Default fixtures use isolated files and disposable signing keys, including a
verbatim public upstream inventory excerpt. With SLS_REAL_FRAMEWORK_INPUTS set,
the complete original packages are also authenticated under the pinned FreePBX
authority. Expected omissions are independent of the product mapper.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('v020_signed_stock_fixture', ROOT / 'tools/test_upgrade_trust.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
OMISSIONS = (
    '.gitattributes', '.langignore', '.vscode/settings.json',
    'utests/API/GQL/ModuleAdminGqlApiTest.php', 'utests/API/GQL/SystemAdminGglApiTest.php',
    'utests/AstmanTest.php', 'utests/CronTest.php', 'utests/DBHelperTest.php',
    'utests/DoctrineTest.php', 'utests/FwconsoleTest.php', 'utests/GPGTest.php',
    'utests/InstallerTest.php', 'utests/LoadConfigTest.php', 'utests/MailTest.php',
    'utests/ModulesTest.php', 'utests/PHPTest.php', 'utests/PKCSTest.php',
    'utests/RealtimeTest.php', 'utests/RequestTest.php', 'utests/UpdatesTest.php',
    'utests/ViewsTest.php', 'utests/WebTest.php', 'utests/genaccts.php')


class NativeProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURE.UpgradeTrustTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        FIXTURE.UpgradeTrustTests.tearDownClass()

    def setUp(self):
        self.fixture = FIXTURE.UpgradeTrustTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.upgrade = self.fixture.upgrade

    def projection(self, version='17.0.33', present=(), signed_tooling=(),
                   upstream_excerpt=False, transform=None):
        f = self.fixture
        contents = {
            'module.xml': ('<module><rawname>framework</rawname><version>' + version + '</version></module>').encode(),
            'amp_conf/htdocs/admin/views/menu_items.php': b"<?php\n\telse if ($a == 'other')\n\t\treturn true;\n",
            'amp_conf/htdocs/admin/images/spinner.gif': b'GIF89a independently specified fixture',
            'amp_conf/htdocs/admin/libraries/BMO/GPG.class.php': b'<?php /* exact authenticated security implementation */\n',
            'amp_conf/htdocs/admin/.htaccess': b'Require all denied\n',
            '.hidden-runtime.php': b'<?php /* must remain covered */\n',
            **{name: ('authenticated tooling ' + name).encode() for name in OMISSIONS}}
        if upstream_excerpt:
            excerpt = json.loads((ROOT / 'tools/fixtures/framework-17.0.33.2-module-sig-excerpt.json').read_text())
            self.assertEqual(version, '17.0.33.2')
            contents.update({name: base64.b64decode(body, validate=True)
                             for name, body in excerpt['files_base64'].items()})
            contents['module.sig'] = (excerpt['header_through_hashes']
                + ''.join(line + '\n' for line in excerpt['hash_records']) + excerpt['ending']).encode()
        else:
            runtime = set(contents) - set(OMISSIONS)
            hashes = runtime | set(signed_tooling)
            contents['module.sig'] = (b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'
                b'[config]\nversion=1\nhash=sha256\n[hashes]\n'
                + b''.join(name.encode() + b' = ' + self.upgrade.TRUST.digest(contents[name]).encode() + b'\n'
                           for name in sorted(hashes))
                + b';# End\n-----BEGIN PGP SIGNATURE-----\nInert embedded signature protected by the real outer signature\n-----END PGP SIGNATURE-----\n')
        if transform is not None:
            contents['module.sig'] = transform(contents['module.sig'])
        runtime = set(contents) - set(OMISSIONS) - {'module.sig'}
        workspace = Path(tempfile.mkdtemp(prefix='projection-' + version + '-', dir=f.root))
        plain = workspace / 'framework.tgz'
        FIXTURE.package(plain, 'framework', contents)
        signed = workspace / ('framework-' + version + '.tgz.gpg')
        subprocess.run(f.gpg_command + ['--output', str(signed), '--sign', str(plain)],
                       check=True, capture_output=True, timeout=20)
        authenticated, source = self.upgrade.upstream_contents(signed, 'framework', version, workspace)
        web = workspace / 'web'
        for name in runtime | set(present):
            target = web / (name[16:] if name.startswith('amp_conf/htdocs/') else 'admin/modules/framework/' + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents[name])
        data, prior = self.upgrade.upstream_inventory(authenticated, source, 'framework', version,
                                                     f.new, f.old, web)
        return contents, web, data, prior

    def test_authenticated_native_fresh_layouts_pass_without_installing_tooling(self):
        # A mapper that again makes the archive-only tooling mandatory must fail.
        for version in ('17.0.33', '17.0.33.1', '17.0.33.2', '17.0.33.3',
                        '17.0.33.4', '17.0.33.5', '17.0.34'):
            with self.subTest(version=version):
                contents, web, data, prior = self.projection(version)
                self.assertEqual(self.upgrade.compare_stock(data, prior, web, self.fixture.new), [])
                self.assertEqual(sorted(data['source']['installed_projection']['omitted_paths']), sorted(OMISSIONS))
                self.assertEqual(data['source']['installed_projection']['version'], version)
                for name in OMISSIONS:
                    self.assertNotIn(name, data['files'])

    def test_verbatim_upstream_comment_keeps_real_runtime_hashes_and_native_omissions(self):
        try:
            contents, web, data, prior = self.projection('17.0.33.2', upstream_excerpt=True)
        except self.upgrade.UpgradeError as error:
            self.fail('The authenticated upstream inventory comment must not reject native stock: ' + str(error))
        self.assertEqual(self.upgrade.compare_stock(data, prior, web, self.fixture.new), [])
        self.assertEqual(set(data['source']['installed_projection']['omitted_paths']), set(OMISSIONS))
        self.assertEqual(data['files']['amp_conf/htdocs/admin/libraries/BMO/GPG.class.php']['sha256'],
                         '29b29383f0817d3f96facd9955c7305c7f4de1fc317fd2fac1879004310d722d')
        (web / 'admin/libraries/BMO/GPG.class.php').write_bytes(b'<?php /* unreviewed runtime change */')
        self.assertEqual({item['path'] for item in self.upgrade.compare_stock(data, prior, web, self.fixture.new)},
                         {'amp_conf/htdocs/admin/libraries/BMO/GPG.class.php'})

    def test_authenticated_comments_do_not_waive_malformed_duplicate_unsafe_or_wrong_hash_records(self):
        excerpt = json.loads((ROOT / 'tools/fixtures/framework-17.0.33.2-module-sig-excerpt.json').read_text())
        record = excerpt['hash_records'][0].encode()
        cases = {
            'malformed record': b'not an inventory record',
            'unknown section': b'[unreviewed]',
            'duplicate path': record,
            'unsafe path': b'../escape = ' + b'0' * 64,
            'missing path': b'unavailable.php = ' + b'0' * 64,
            'wrong digest': record.split(b' = ')[0] + b' = ' + b'0' * 64,
        }
        for reason, extra in cases.items():
            with self.subTest(reason=reason), self.assertRaises(self.upgrade.UpgradeError):
                self.projection('17.0.33.2', upstream_excerpt=True,
                                transform=(lambda body, line=extra: body.replace(record, line, 1))
                                if reason == 'wrong digest' else
                                (lambda body, line=extra: body.replace(b';# End\n', line + b'\n;# End\n')))

    def test_present_tooling_is_still_covered_and_changed_gpg_still_refused(self):
        contents, web, data, prior = self.projection(present=('.gitattributes',))
        self.assertIn('.gitattributes', data['files'])
        (web / 'admin/modules/framework/.gitattributes').write_bytes(b'changed tooling')
        (web / 'admin/libraries/BMO/GPG.class.php').write_bytes(b'<?php /* unknown patch */')
        issues = self.upgrade.compare_stock(data, prior, web, self.fixture.new)
        self.assertEqual({item['path'] for item in issues}, {'.gitattributes', 'amp_conf/htdocs/admin/libraries/BMO/GPG.class.php'})

    def test_missing_runtime_and_hidden_php_never_become_native_omissions(self):
        contents, web, data, prior = self.projection()
        (web / 'admin/.htaccess').unlink()
        (web / 'admin/modules/framework/.hidden-runtime.php').unlink()
        issues = self.upgrade.compare_stock(data, prior, web, self.fixture.new)
        self.assertEqual({item['path'] for item in issues}, {'amp_conf/htdocs/admin/.htaccess', '.hidden-runtime.php'})

    def test_unqualified_upstream_version_keeps_missing_tooling_mandatory(self):
        contents, web, data, prior = self.projection('17.0.33.99')
        self.assertEqual({item['path'] for item in self.upgrade.compare_stock(data, prior, web, self.fixture.new)}, set(OMISSIONS))

    def test_embedded_inventory_cannot_lose_a_required_tooling_path(self):
        contents, web, data, prior = self.projection(signed_tooling=('.gitattributes',))
        issues = self.upgrade.compare_stock(data, prior, web, self.fixture.new)
        self.assertEqual({item['path'] for item in issues}, {'.gitattributes'})

    def test_later_missing_previously_enrolled_tooling_does_not_reduce_old_authority(self):
        contents, web, data, prior = self.projection(present=('.gitattributes',))
        (web / 'admin/modules/framework/.gitattributes').unlink()
        self.assertEqual({item['path'] for item in self.upgrade.compare_stock(data, prior, web, self.fixture.new)}, {'.gitattributes'})


if os.environ.get('SLS_REAL_FRAMEWORK_INPUTS'):
    class GenuineFrameworkProjection(unittest.TestCase):
        """Optional complete public archives, with no test-key authority override."""
        EXPECTED = {
            '17.0.33': ('6f3cc91e62b937c270fc52f87483f8bce948d3c7953ea76fd4d7e01955e0cc75',
                        '04fafb51cdb7272a37ce106f9dadf4184a583ae69d9a93b72a81034fafe9d6b0',
                        '8d9adabf8ec5f0e19695cae4f82a18d3d203c91e64c85ac002d2cce1bf5ae581'),
            '17.0.33.2': ('783cf4f802791f38231c1f4ba6e374eaea7f4adcbb97cec2fba7f6c552b1baa9',
                          '01ac0cda90cea7c131abbd43edd2af0ce9d702224b5a45e3076669c010639ebc',
                          'b00a39d8661e76f77b8d431a15e09f43e54fadf5babb077b153df4e5d6cb71ee'),
            '17.0.33.4': ('868a4e1d3b753045f9137bbb5631abe298b30cf6cacdc5798958271c94ffbacf',
                          'a704ac97807126a3047b22d261a3bbd532805da697817c78fd2b4f7e6cf98a18',
                          '98211d86dfe0e897efaf11d325f84605cf7dde377e6535847b6e29a64b82460d'),
        }

        @classmethod
        def setUpClass(cls):
            cls.inputs = Path(os.environ['SLS_REAL_FRAMEWORK_INPUTS'])
            cls.temporary = tempfile.TemporaryDirectory(prefix='sls-real-framework-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.root = Path(cls.temporary.name)
            helpers = cls.root / 'helpers'
            helpers.mkdir(mode=0o700)
            original = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
            for name in ('sls_upgrade_trust.py', 'sls_module_trust.py', 'sls_release_trust.py',
                         'sls_installer_recovery.py', 'freepbx-mirror-signing.pub'):
                (helpers / name).write_bytes((original / name).read_bytes())
            spec = importlib.util.spec_from_file_location('genuine_upstream_framework', helpers / 'sls_upgrade_trust.py')
            cls.upgrade = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.upgrade)
            cls.authenticated = {}
            for version, expected in cls.EXPECTED.items():
                name = 'framework-' + version + '.tgz.gpg'
                body = (cls.inputs / name).read_bytes()
                if hashlib.sha256(body).hexdigest() != expected[0]:
                    raise AssertionError('Genuine signed Framework fixture identity changed: ' + version)
                signed = cls.root / name
                signed.write_bytes(body)
                signed.chmod(0o600)
                contents, source = cls.upgrade.upstream_contents(signed, 'framework', version, cls.root)
                if (source['archive_sha256'] != expected[1]
                        or hashlib.sha256(contents['module.sig']).hexdigest() != expected[2]):
                    raise AssertionError('Authenticated Framework plaintext identity changed: ' + version)
                cls.authenticated[version] = (contents, source)

        def test_additional_signed_versions_against_real_file_and_embedded_hashes(self):
            # Work on one complete package at a time on 2 GiB qualification hosts.
            expected = {
                '17.0.33.1': '1afe3cbd28531b760d32afcc2f9579aa992a81e5b86570a44f60432042fd9bd2',
                '17.0.33.3': 'c43542bd51b1d22ee54dd898be3788afc337910adad3a6538948548b499581cf',
                '17.0.33.5': '8d38efbc738e209006230f24f97e3d4be02cfd3fc8af848cc1bb806ae37422d6',
                '17.0.34': 'd1afd8e703b8146752909778160b816ea08b214112d1d2f856b8f97e56439cca',
            }
            supplied = {v: self.inputs / ('framework-' + v + '.tgz.gpg') for v in expected}
            if not any(path.exists() for path in supplied.values()):
                self.skipTest('Additional signed stock packages were not supplied')
            for version, package in supplied.items():
                with self.subTest(version=version), tempfile.TemporaryDirectory(dir=self.root) as name:
                    web = Path(name)
                    signed = web / package.name
                    body = package.read_bytes()
                    self.assertEqual(hashlib.sha256(body).hexdigest(), expected[version])
                    signed.write_bytes(body)
                    contents, source = self.upgrade.upstream_contents(signed, 'framework', version, web)
                    data, prior = self.upgrade.upstream_inventory(contents, source, 'framework', version, {}, {}, web)
                    omitted = data['source'].get('installed_projection', {}).get('omitted_paths', [])
                    self.assertEqual(set(omitted), set(OMISSIONS))
                    gpg = 'amp_conf/htdocs/admin/libraries/BMO/GPG.class.php'
                    self.assertEqual(data['files'][gpg]['sha256'], hashlib.sha256(contents[gpg]).hexdigest())
                    self.assertEqual(data['files'][gpg]['target'], 'admin/libraries/BMO/GPG.class.php')
                    del contents, data, prior

        def test_complete_genuine_inventories_allow_only_exact_qualified_missing_tooling(self):
            for version, (contents, source) in self.authenticated.items():
                with self.subTest(version=version), tempfile.TemporaryDirectory(dir=self.root) as name:
                    web = Path(name)
                    try:
                        data, prior = self.upgrade.upstream_inventory(contents, source, 'framework', version, {}, {}, web)
                    except self.upgrade.UpgradeError as error:
                        self.fail('The complete authenticated upstream inventory must accept native stock: ' + str(error))
                    self.assertEqual(set(data['source']['installed_projection']['omitted_paths']), set(OMISSIONS))
                    self.assertEqual(data['source']['installed_projection']['embedded_inventory_sha256'], self.EXPECTED[version][2])
                    self.assertFalse(set(OMISSIONS) & set(data['files']))
                    # This real runtime file is absent from the embedded list;
                    # outer-authenticated bytes must still remain mandatory.
                    self.assertIn('amp_conf/htdocs/admin/.user.ini', data['files'])
                    for relative, entry in data['files'].items():
                        target = web / entry['target']
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(contents[relative])
                    self.assertEqual(self.upgrade.compare_stock(data, prior, web, {}), [])
                    (web / 'admin/.user.ini').unlink()
                    self.assertEqual({row['path'] for row in self.upgrade.compare_stock(data, prior, web, {})},
                                     {'amp_conf/htdocs/admin/.user.ini'})
                    present = web / 'admin/modules/framework/.gitattributes'
                    present.write_bytes(contents['.gitattributes'])
                    with_tooling, previous = self.upgrade.upstream_inventory(contents, source, 'framework', version, {}, {}, web)
                    self.assertIn('.gitattributes', with_tooling['files'])
                    present.unlink()
                    self.assertIn('.gitattributes', {row['path'] for row in self.upgrade.compare_stock(with_tooling, previous, web, {})})

        def test_complete_genuine_inventory_rejects_bad_records_and_changed_covered_bytes(self):
            for version, (original, source) in self.authenticated.items():
                first_record = original['module.sig'].split(b'[hashes]\n', 1)[1].splitlines()[0]
                for reason, line in (('duplicate', first_record), ('unsafe', b'../escape = ' + b'0' * 64),
                                     ('missing', b'not-in-package.php = ' + b'0' * 64),
                                     ('unknown section', b'[unreviewed]'), ('malformed', b'not a record')):
                    contents = dict(original)
                    contents['module.sig'] = contents['module.sig'].replace(b';# End\n', line + b'\n;# End\n')
                    with self.subTest(version=version, reason=reason), self.assertRaises(self.upgrade.UpgradeError):
                        self.upgrade.native_framework_projection(contents, source, version, self.root)
                for change in ('changed', 'missing'):
                    contents = dict(original)
                    if change == 'changed':
                        contents['amp_conf/htdocs/admin/libraries/BMO/GPG.class.php'] += b'\n/* unknown */\n'
                    else:
                        del contents['amp_conf/htdocs/admin/libraries/BMO/GPG.class.php']
                    with self.subTest(version=version, reason=change), self.assertRaises(self.upgrade.UpgradeError):
                        self.upgrade.native_framework_projection(contents, source, version, self.root)

        def test_unsigned_or_changed_outer_archive_never_supplies_native_authority(self):
            signed = (self.inputs / 'framework-17.0.33.2.tgz.gpg').read_bytes()
            plain = self.inputs / 'framework-17.0.33.2.tgz'
            for name, body in (('unsigned', plain.read_bytes()),
                               ('changed', signed[:len(signed)//2] + bytes([signed[len(signed)//2] ^ 1]) + signed[len(signed)//2+1:])):
                path = self.root / (name + '.tgz.gpg')
                path.write_bytes(body)
                with self.subTest(reason=name), self.assertRaises(self.upgrade.UpgradeError):
                    self.upgrade.upstream_contents(path, 'framework', '17.0.33.2', self.root)


GENERATION_CHILD = r'''
import importlib.util,os,signal,sys
from pathlib import Path
helper,root,inventory,digest=sys.argv[1:]
spec=importlib.util.spec_from_file_location('v020_generation_child',helper)
trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(trust)
real=trust.os.replace
def boundary(source,target,*args,**kwargs):
    if str(target)=='inventory.json':
        print('inventory-ready',flush=True);os.kill(os.getpid(),signal.SIGSTOP)
    return real(source,target,*args,**kwargs)
trust.os.replace=boundary
trust.enroll_reviewed(Path(root),Path(inventory),digest)
'''


class ReviewedGenerationRetry(unittest.TestCase):
    def test_exact_reviewed_retry_survives_own_writer_death_without_losing_previous_approval(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='sls-v020-generation-', dir='/run') as name:
            root = Path(name)
            helper = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py'
            spec = importlib.util.spec_from_file_location('v020_generation', helper)
            trust = importlib.util.module_from_spec(spec); spec.loader.exec_module(trust)
            store = root / 'trust'
            def candidate(version):
                data = {'schema': 1, 'module': 'dashboard', 'version': version,
                        'source': {'kind': 'reviewed-upstream-and-overlays', 'archive_sha256': 'a' * 64},
                        'files': {'module.xml': {'sha256': 'b' * 64, 'target': 'admin/modules/dashboard/module.xml'}}}
                body = json.dumps(data, sort_keys=True).encode()
                path = root / ('review-' + version + '.json'); path.write_bytes(body);path.chmod(0o600)
                return path, trust.digest(body)
            old, old_digest = candidate('17.0.33')
            trust.enroll_reviewed(store, old, old_digest)
            reference = store / 'dashboard.active.json'
            previous = reference.read_bytes()
            new, new_digest = candidate('17.0.33.2')
            child = subprocess.Popen([sys.executable, '-I', '-c', GENERATION_CHILD,
                                      str(helper), str(store), str(new), new_digest],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                self.assertEqual(child.stdout.readline(), 'inventory-ready\n')
                child.kill();child.communicate(timeout=5)
                self.assertEqual(child.returncode, -signal.SIGKILL)
                self.assertEqual(reference.read_bytes(), previous)
                trust.enroll_reviewed(store, new, new_digest)
                self.assertEqual(trust.load(store, 'dashboard')[0]['version'], '17.0.33.2')
                self.assertEqual((store / ('dashboard-' + old_digest) / 'inventory.json').read_bytes(), old.read_bytes())
            finally:
                if child.poll() is None:child.kill();child.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
