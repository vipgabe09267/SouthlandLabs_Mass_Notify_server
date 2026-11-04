#!/usr/bin/env python3
"""Real Ed25519 verification fixtures; no network or production signing key."""
import importlib.util
import contextlib
import hashlib
import io
import os
import textwrap
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manifest_fixture', ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_release_verify.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
docs_spec = importlib.util.spec_from_file_location('release_docs_fixture', ROOT / 'tools/check_release_docs.py')
release_docs = importlib.util.module_from_spec(docs_spec)
docs_spec.loader.exec_module(release_docs)


class ReleaseDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sls-release-docs-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('docs/schemas', 'slsmassnotifyserver/docs/schemas', 'tools'):
            (self.root / name).mkdir(parents=True)
        self.version = '0.1.9-beta'
        (self.root / 'slsmassnotifyserver/module.xml').write_text('<module><version>' + self.version + '</version></module>')
        bootstrap = b'fixture bootstrap bytes'
        (self.root / 'tools/install_bootstrap.sh').write_bytes(bootstrap)
        (self.root / 'README.md').write_text(hashlib.sha256(bootstrap).hexdigest() + '  sls-bootstrap.sh\nbash sls-bootstrap.sh ' + self.version)
        self.record = {'schema': 1, 'published_version': self.version, 'candidate_version': self.version,
                       'candidate_status': 'published', 'purpose': 'Documentation state only.'}
        self.write_state()

    def write_state(self):
        contents = {'release-status.json': json.dumps(self.record),
                    'QUALIFICATION_MATRIX.md': self.version + ' is ' + self.record['candidate_status'] + '.',
                    'CONTROL_API.md': 'The ' + self.record['candidate_status'] + ' ' + self.version + ' API.',
                    'openapi.json': '{}', 'schemas/notification.schema.json': '{}'}
        for name, text in contents.items():
            for prefix in ('docs', 'slsmassnotifyserver/docs'):
                (self.root / prefix / name).write_text(text)
        (self.root / 'SECURITY.md').write_text('Supported prerelease: currently `' + self.record['published_version'] + '`.')

    def check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            release_docs.check(self.root)

    def test_published_and_newer_unpublished_documentation(self):
        self.check()
        self.record.update(candidate_status='unpublished', published_version='0.1.7-beta')
        self.write_state()
        self.check()

    def test_current_repository_documentation(self):
        with contextlib.redirect_stdout(io.StringIO()):
            release_docs.check()

    def test_rejects_mismatched_or_ambiguous_release_states(self):
        invalid = [dict(self.record, schema=True), dict(self.record, extra=True),
                   dict(self.record, purpose=''), dict(self.record, candidate_version='0.1.8-beta'),
                   dict(self.record, candidate_status='unknown'), dict(self.record, candidate_status=False),
                   dict(self.record, candidate_status='unpublished'),
                   dict(self.record, candidate_status='unpublished', published_version='0.1.9-beta'),
                   dict(self.record, published_version='0.1.7-beta'),
                   dict(self.record, published_version='0.1.08-beta'),
                   dict(self.record, published_version='invalid'), []]
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(ValueError):
                release_docs.release_state(record, self.version)

    def test_rejects_stale_published_intros_and_packaged_state(self):
        for name in ('CONTROL_API.md', 'QUALIFICATION_MATRIX.md'):
            with self.subTest(name=name):
                self.write_state()
                (self.root / 'docs' / name).write_text(self.version + ' is unpublished.')
                with self.assertRaisesRegex(ValueError, 'release state'): self.check()
        self.write_state()
        (self.root / 'slsmassnotifyserver/docs/release-status.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Packaged documentation'): self.check()

    def test_rejects_stale_bootstrap_and_security_version(self):
        (self.root / 'tools/install_bootstrap.sh').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'bootstrap checksum'): self.check()
        (self.root / 'tools/install_bootstrap.sh').write_bytes(b'fixture bootstrap bytes')
        (self.root / 'SECURITY.md').write_text('currently `0.1.7-beta`')
        with self.assertRaisesRegex(ValueError, 'published version'): self.check()


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key, self.public = self.root / 'private', self.root / 'public'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(self.key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.public)], check=True, capture_output=True)
        self.installer, self.package = self.root / 'installer', self.root / 'package'
        self.installer.write_bytes(b'fixture installer')
        self.package.write_bytes(b'fixture archive')
        self.manifest, self.signature = self.root / 'manifest', self.root / 'signature'
        self.data = {'schema': 1, 'version': '0.1.2-beta', 'tag': 'slsmassnotifyserver-0.1.2-beta',
                     'package': 'slsmassnotifyserver-0.1.2-beta.tgz',
                     'installer_sha256': verifier.digest(self.installer), 'package_sha256': verifier.digest(self.package)}
        self.sign()

    def sign(self):
        self.manifest.write_text(json.dumps(self.data))
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key),
                        '-in', str(self.manifest), '-out', str(self.signature)], check=True, capture_output=True)

    def verify(self):
        return verifier.verify(self.manifest, self.signature, self.installer, self.package, '0.1.2-beta', self.public, trust_directory=self.root/'trust')

    def test_valid(self):
        self.assertEqual(self.verify(), self.data)

    def test_v_tag_preserves_signed_version_and_artifact_binding(self):
        self.data['tag'] = 'v0.1.2-beta'
        self.sign()
        try:
            verified = self.verify()
        except ValueError as error:
            self.fail('A valid signed v tag was rejected: '+str(error))
        self.assertEqual(verified, self.data)
        self.package.write_bytes(b'changed archive')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()

    def test_uppercase_current_tag_is_exact_and_event_tag_cannot_be_replayed(self):
        self.data.update(version='0.1.9-beta',tag='V0.1.9-beta',package='slsmassnotifyserver-0.1.9-beta.tgz')
        self.sign()
        args=(self.manifest,self.signature,self.installer,self.package,'0.1.9-beta',self.public)
        self.assertEqual(verifier.verify(*args,trust_directory=self.root/'trust'),self.data)
        with self.assertRaisesRegex(ValueError,'identity'):
            verifier.verify(*args,trust_directory=self.root/'trust',expected_tag='v0.1.9-beta')
        self.data.update(version='0.1.10-beta',tag='V0.1.10-beta',package='slsmassnotifyserver-0.1.10-beta.tgz')
        self.sign()
        with self.assertRaisesRegex(ValueError,'identity'):
            verifier.verify(self.manifest,self.signature,self.installer,self.package,'0.1.10-beta',self.public,trust_directory=self.root/'trust')

    def test_exact_release_alias_binds_version_artifacts_and_expected_event_tag(self):
        self.data.update(version='0.1.9-beta',tag='release-0.1.9-beta',package='slsmassnotifyserver-0.1.9-beta.tgz')
        self.sign()
        args=(self.manifest,self.signature,self.installer,self.package,'0.1.9-beta',self.public)
        self.assertEqual(verifier.verify(*args,trust_directory=self.root/'trust',expected_tag='release-0.1.9-beta'),self.data)
        for historical in ('v0.1.9-beta','V0.1.9-beta','slsmassnotifyserver-0.1.9-beta'):
            with self.subTest(historical=historical),self.assertRaisesRegex(ValueError,'identity'):
                verifier.verify(*args,trust_directory=self.root/'trust',expected_tag=historical)
        self.package.write_bytes(b'changed archive')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):
            verifier.verify(*args,trust_directory=self.root/'trust',expected_tag='release-0.1.9-beta')

    def test_release_alias_does_not_open_a_new_tag_namespace(self):
        for version,tag in (('0.1.8-beta','release-0.1.8-beta'),('0.1.10-beta','release-0.1.10-beta'),
                            ('0.1.10-beta','release-0.1.9-beta'),('0.1.9-beta','Release-0.1.9-beta'),
                            ('0.1.9-beta','release-0.1.9'),('0.1.9-beta','release-0.1.9-beta/other')):
            with self.subTest(version=version,tag=tag):
                self.data.update(version=version,tag=tag,package='slsmassnotifyserver-'+version+'.tgz');self.sign()
                with self.assertRaisesRegex(ValueError,'identity'):
                    verifier.verify(self.manifest,self.signature,self.installer,self.package,version,self.public,trust_directory=self.root/'trust')

    def test_signed_tag_cannot_change_version_or_escape_its_namespace(self):
        for tag in ('v0.1.1-beta', 'v0.1.2-beta-extra', 'v0.1.2-beta/other', 'slsmassnotifyserver-0.1.1-beta'):
            with self.subTest(tag=tag):
                self.data['tag'] = tag
                self.sign()
                with self.assertRaisesRegex(ValueError, 'identity'):
                    self.verify()

    def test_release_workflow_accepts_v_and_legacy_tags_but_rejects_unsafe_names(self):
        source = (ROOT / '.github/workflows/release-provenance.yml').read_text()
        script = textwrap.dedent(source.split('- name: Validate release identity', 1)[1].split('run: |\n', 1)[1].split('      - uses:', 1)[0])
        for tag, allowed in (('release-0.1.9-beta', True), ('release-0.1.8-beta', False), ('release-0.1.10-beta', False), ('release-0.1.9', False), ('Release-0.1.9-beta', False), ('release-0.1.9-beta\n', False), ('release-0.1.9-beta/other', False), ('V0.1.9-beta', True), ('V0.1.10-beta', False), ('V0.1.9', False), ('v0.1.9-beta', True), ('slsmassnotifyserver-0.1.8-beta', True), ('v0.1.9-beta\n', False), ('v0.1.9-beta;id', False), ('../v0.1.9-beta', False)):
            with self.subTest(tag=tag):
                result = subprocess.run(['bash', '-c', script], env={**os.environ, 'SLS_RELEASE_TAG':tag,'GITHUB_REPOSITORY':'vipgabe09267/SouthlandLabs_Mass_Notify_server','GITHUB_REF':'refs/tags/'+tag}, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_release_workflow_rejects_other_repository_and_replayed_event_ref(self):
        source=(ROOT/'.github/workflows/release-provenance.yml').read_text()
        script=textwrap.dedent(source.split('- name: Validate release identity',1)[1].split('run: |\n',1)[1].split('      - uses:',1)[0])
        for overrides in ({'GITHUB_REPOSITORY':'other/SouthlandLabs_Mass_Notify_server'},
                          {'GITHUB_REF':'refs/heads/main'},{'GITHUB_REF':'refs/tags/slsmassnotifyserver-0.1.9-beta'}):
            env={**os.environ,'SLS_RELEASE_TAG':'v0.1.9-beta','GITHUB_REPOSITORY':'vipgabe09267/SouthlandLabs_Mass_Notify_server','GITHUB_REF':'refs/tags/v0.1.9-beta',**overrides}
            result=subprocess.run(['bash','-c',script],env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0,result.stderr)
        self.assertIn('--tag "$SLS_RELEASE_TAG"',source)

    def test_release_workflow_downloads_canonical_package_for_exact_alias(self):
        source=(ROOT/'.github/workflows/release-provenance.yml').read_text()
        script=textwrap.dedent(source.split('- name: Require immutable release and verify publisher signature',1)[1].split('run: |\n',1)[1].split('      - name:',1)[0])
        fixture=self.root/'workflow';fixture.mkdir()
        executable=fixture/'gh'
        executable.write_text('#!/usr/bin/python3\nimport json,os,sys\n'
            'if sys.argv[1]=="api":\n'
            ' print(json.dumps({"tag_name":os.environ["SLS_RELEASE_TAG"],"draft":False,"immutable":True}))\n'
            'elif sys.argv[1:3]==["release","download"]:\n'
            ' open(os.environ["SLS_DOWNLOAD_ARGUMENTS"],"w").write(json.dumps(sys.argv[1:]))\n'
            ' raise SystemExit(79)\n'
            'else: raise SystemExit(91)\n')
        executable.chmod(0o700)
        arguments=fixture/'download.json'
        env={**os.environ,'PATH':str(fixture)+os.pathsep+os.environ['PATH'],
             'SLS_RELEASE_TAG':'release-0.1.9-beta',
             'GITHUB_REPOSITORY':'vipgabe09267/SouthlandLabs_Mass_Notify_server',
             'SLS_DOWNLOAD_ARGUMENTS':str(arguments)}
        result=subprocess.run(['bash','-ec',script],cwd=fixture,env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,79,result.stderr)
        downloaded=json.loads(arguments.read_text())
        self.assertEqual(downloaded[:3],['release','download','release-0.1.9-beta'])
        self.assertEqual([downloaded[index+1] for index,item in enumerate(downloaded) if item=='--pattern'],
                         ['slsmassnotifyserver-0.1.9-beta.tgz','release-manifest.json','release-manifest.sig'])

    def test_rejects_modified_manifest(self):
        self.manifest.write_text(self.manifest.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.verify()

    def test_rejects_modified_installer(self):
        self.installer.write_bytes(b'changed installer')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()

    def test_rejects_modified_archive(self):
        self.package.write_bytes(b'changed archive')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()

    def test_rejects_signed_wrong_version(self):
        self.data['version'] = '0.1.1-beta'
        self.sign()
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.verify()

    def test_installer_pins_same_public_key(self):
        key_lines = (ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/release-signing.pub').read_text().strip().splitlines()
        self.assertIn(key_lines[1], (ROOT / 'tools/install_release.sh').read_text())

    def test_updater_verifies_before_execution_and_reuses_authenticated_bytes(self):
        source = (ROOT / 'slsmassnotifyserver/bin/sls_mass_notify_update.sh').read_text()
        self.assertLess(source.index('--manifest "$release_manifest"'), source.index('chmod 0700 "$tmp_script"'))
        self.assertIn('SLS_MASS_NOTIFY_TGZ="$release_package" SLS_MASS_NOTIFY_TGZ_URL=\'\'', source)


if __name__ == '__main__':
    unittest.main()
