#!/usr/bin/python3
"""Exercise the standalone pre-execution verifier with a private ephemeral key."""
import hashlib
import importlib.util
import io
import re
import tarfile
import shutil
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "tools/install_bootstrap.sh"


class VerifiedBootstrap(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sls-bootstrap-")
        self.path = Path(self.temporary.name)
        self.version = "0.1.9-beta"
        self.marker = self.path / "executed"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                str(self.path / "private.pem"),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.path / "private.pem"),
                "-pubout",
                "-out",
                str(self.path / "publisher.pem"),
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.check_output(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.path / "private.pem"),
                "-pubout",
                "-outform",
                "DER",
            ]
        )
        self.public_der = der
        self.installer = (
            b"#!/bin/bash\nprintf verified > " + str(self.marker).encode() + b"\n"
        )
        (self.path / "install_release.sh").write_bytes(self.installer)
        self.manifest = {
            "schema": 1,
            "version": self.version,
            "tag": "slsmassnotifyserver-" + self.version,
            "package": "slsmassnotifyserver-" + self.version + ".tgz",
            "package_sha256": "a" * 64,
            "installer_sha256": hashlib.sha256(self.installer).hexdigest(),
            "signing": {
                "key_id": hashlib.sha256(der).hexdigest(),
                "issued_at": int(time.time()) - 1,
                "expires_at": int(time.time()) + 300,
            },
        }

    def tearDown(self):
        self.temporary.cleanup()

    def sign(self, raw=None):
        (self.path / "release-manifest.json").write_text(
            json.dumps(self.manifest) if raw is None else raw
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.path / "private.pem"),
                "-rawin",
                "-in",
                str(self.path / "release-manifest.json"),
                "-out",
                str(self.path / "release-manifest.sig"),
            ],
            check=True,
            capture_output=True,
        )

    def execute(self):
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; bootstrap_verify "$2" "$3" && /bin/bash "$2/install_release.sh"',
                "fixture",
                str(BOOTSTRAP),
                str(self.path),
                self.version,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_correct_signed_bytes_execute_only_after_verification(self):
        self.sign()
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), "verified")

    def test_v_tag_executes_only_the_matching_signed_installer(self):
        self.manifest['tag'] = 'v0.1.9-beta'
        self.sign()
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), 'verified')

    def test_exact_uppercase_current_tag_is_allowed_but_other_uppercase_tags_are_not(self):
        self.manifest['tag']='V0.1.9-beta';self.sign()
        result=self.execute();self.assertEqual(result.returncode,0,result.stderr)
        self.marker.unlink()
        self.version='0.1.10-beta';self.manifest.update(version=self.version,tag='V'+self.version,package='slsmassnotifyserver-'+self.version+'.tgz');self.sign()
        self.assertNotEqual(self.execute().returncode,0)
        self.assertFalse(self.marker.exists())

    def test_download_selects_exact_candidate_or_historical_prefix_without_execution(self):
        code=BOOTSTRAP.read_text().split('bootstrap_download() {',1)[1].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        for version,tag in [('0.1.8-beta','slsmassnotifyserver-0.1.8-beta'),('0.1.9-beta','V0.1.9-beta'),('0.1.10-beta','v0.1.10-beta')]:
            destination=self.path/version;destination.mkdir()
            urls=[]
            class Reply(io.BytesIO):
                status=200
            def open_asset(request,**kwargs):
                urls.append(request.full_url);return Reply(b'inert authenticated-input fixture')
            with patch('sys.argv',['bootstrap',str(destination),version]), patch('urllib.request.build_opener') as client:
                client.return_value.open.side_effect=open_asset
                exec(compile(code,'<shipped bootstrap download>','exec'),{})
            self.assertEqual(len(urls),3)
            self.assertTrue(all('/'+tag+'/' in url for url in urls),urls)
            self.assertFalse(self.marker.exists())

    def test_existing_policy_revocation_is_checked_before_execution(self):
        if os.geteuid() != 0 or os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
            self.skipTest('Requires the isolated root fixture')
        helper = Path('/usr/local/bin/sls_mass_notify/sls_release_trust.py')
        previous = helper.read_bytes() if helper.exists() else None
        previous_mode = helper.stat().st_mode & 0o777 if helper.exists() else None
        helper.write_bytes((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_release_trust.py').read_bytes())
        helper.chmod(0o600)
        def restore():
            if previous is None:
                helper.unlink(missing_ok=True)
            else:
                helper.write_bytes(previous)
                helper.chmod(previous_mode)
        self.addCleanup(restore)
        spec = importlib.util.spec_from_file_location('bootstrap_policy_fixture', helper)
        trust = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trust)
        policy_path = Path(tempfile.mkdtemp(prefix='sls-bootstrap-policy-', dir='/run'))
        self.addCleanup(shutil.rmtree, policy_path)
        store = trust.TrustStore(policy_path, (self.path/'publisher.pem').read_bytes())
        store.initialize()
        fixture = self.path/'existing-bootstrap.sh'
        fixture.write_text(BOOTSTRAP.read_text().replace('/var/lib/sls-mass-notify-trust', str(policy_path)))
        self.manifest['tag'] = 'v0.1.9-beta'
        self.sign()
        command = 'source "$1"; bootstrap_verify "$2" "$3" "v$3" 1 && /bin/bash "$2/install_release.sh"'
        args = ['bash','-c',command,'fixture',str(fixture),str(self.path),self.version]
        result = subprocess.run(args,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(self.marker.exists())
        self.marker.unlink()
        state, initialized = store.load()
        self.assertTrue(initialized)
        state['policy']['keys'][0]['revoked_at'] = int(time.time())-1
        store.state.write_bytes(trust.canonical(state))
        before = {x.name:x.read_bytes() for x in policy_path.iterdir() if x.is_file()}
        result = subprocess.run(args,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0,'Revoked publisher was allowed to execute an upgrade')
        self.assertFalse(self.marker.exists())
        self.assertEqual({x.name:x.read_bytes() for x in policy_path.iterdir() if x.is_file()},before)
        state['policy']['keys'][0]['revoked_at'] = 0
        store.state.write_bytes(trust.canonical(state))
        current_key=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/release-signing.pub').read_text().strip()
        fixture.write_text(fixture.read_text().replace(current_key,(self.path/'publisher.pem').read_text().strip()))
        self.manifest['tag']='V0.1.9-beta';self.sign()
        command = 'source "$1"; fixture_assets="$2"; bootstrap_download(){ cp "$fixture_assets/install_release.sh" "$fixture_assets/release-manifest.json" "$fixture_assets/release-manifest.sig" "$1/"; }; bootstrap_main "$3" --upgrade'
        result=subprocess.run(['bash','-c',command,'fixture',str(fixture),str(self.path),self.version],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(self.marker.exists())
        self.marker.unlink()
        module_helper=helper.with_name('sls_module_trust.py')
        previous_module=module_helper.read_bytes() if module_helper.exists() else None
        previous_module_mode=module_helper.stat().st_mode&0o777 if module_helper.exists() else None
        module_source=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py').read_text()
        module_source,count=re.subn(r'^PUBLIC_KEY = .*$',lambda unused:'PUBLIC_KEY = '+repr((self.path/'publisher.pem').read_bytes()),module_source,flags=re.M)
        self.assertEqual(count,1)
        module_helper.write_text(module_source);module_helper.chmod(0o600)
        def restore_module():
            if previous_module is None:module_helper.unlink(missing_ok=True)
            else:module_helper.write_bytes(previous_module);module_helper.chmod(previous_module_mode)
        self.addCleanup(restore_module)
        spec=importlib.util.spec_from_file_location('bootstrap_legacy_module_fixture',module_helper)
        module_trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(module_trust)
        legacy_path=Path(tempfile.mkdtemp(prefix='sls-bootstrap-legacy-',dir='/run'))
        self.addCleanup(shutil.rmtree,legacy_path)
        def enroll(version):
            archive=self.path/('slsmassnotifyserver-'+version+'.tgz')
            body=('<module><rawname>slsmassnotifyserver</rawname><version>'+version+'</version></module>').encode()
            with tarfile.open(archive,'w:gz') as tar:
                info=tarfile.TarInfo('slsmassnotifyserver/module.xml');info.size=len(body);tar.addfile(info,io.BytesIO(body))
            manifest=dict(self.manifest,version=version,tag='slsmassnotifyserver-'+version,package=archive.name,package_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
            path=self.path/'previous-manifest.json';signature=self.path/'previous-manifest.sig';path.write_text(json.dumps(manifest))
            subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.path/'private.pem'),'-in',str(path),'-out',str(signature)],check=True,capture_output=True)
            module_trust.enroll_sls(legacy_path,archive,path,signature)
        enroll('0.1.8-beta')
        legacy_fixture=self.path/'legacy-bootstrap.sh'
        diagnostic=fixture.read_text().replace(str(policy_path),str(legacy_path))
        diagnostic=diagnostic.replace('except (OSError,ValueError,TypeError,KeyError,RuntimeError):','except (OSError,ValueError,TypeError,KeyError,RuntimeError) as error:\n    print(type(error).__name__,str(error),file=sys.stderr)')
        legacy_fixture.write_text(diagnostic)
        legacy_args=['bash','-c','source "$1"; bootstrap_verify "$2" "$3" "V$3" 1 && /bin/bash "$2/install_release.sh"','fixture',str(legacy_fixture),str(self.path),self.version]
        result=subprocess.run(legacy_args,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,'Approved legacy installation was rejected: '+result.stderr)
        self.assertTrue(self.marker.exists());self.marker.unlink()
        self.assertFalse((legacy_path/'publisher-trust.json').exists())
        enroll('0.1.9-beta')
        result=subprocess.run(legacy_args,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,'Approved same-version installation with untouched factory policy was rejected: '+result.stderr)
        self.assertTrue(self.marker.exists());self.marker.unlink()
        self.assertFalse((legacy_path/'publisher-trust.json').exists())
        established=trust.TrustStore(legacy_path,(self.path/'publisher.pem').read_bytes())
        established.initialize()
        saved_state=established.state.read_bytes();saved_marker=established.marker.read_bytes()
        for missing in (established.state,established.marker):
            missing.unlink()
            before={x.name:x.read_bytes() for x in legacy_path.iterdir() if x.is_file()}
            result=subprocess.run(legacy_args,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0,'Incomplete established publisher policy was bypassed')
            self.assertFalse(self.marker.exists())
            self.assertEqual({x.name:x.read_bytes() for x in legacy_path.iterdir() if x.is_file()},before)
            established.state.write_bytes(saved_state);established.state.chmod(0o600)
            established.marker.write_bytes(saved_marker);established.marker.chmod(0o600)

    def test_tampered_installer_is_not_executed(self):
        self.sign()
        (self.path / "install_release.sh").write_bytes(
            self.installer + b"echo changed\n"
        )
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_identity_expiry_future_issued_and_ambiguous_fields_are_rejected(self):
        for field, value in [
            ("version", "0.1.7-beta"),
            ("tag", "v0.1.8-beta"),
            ("package", "../package.tgz"),
            ("schema", True),
        ]:
            with self.subTest(field=field):
                prior = self.manifest[field]
                self.manifest[field] = value
                self.sign()
                result = self.execute()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())
                self.manifest[field] = prior
        for field, value in [
            ("expires_at", int(time.time()) - 1),
            ("issued_at", int(time.time()) + 300),
            ("key_id", "0" * 64),
        ]:
            with self.subTest(field=field):
                prior = self.manifest["signing"][field]
                self.manifest["signing"][field] = value
                self.sign()
                self.assertNotEqual(self.execute().returncode, 0)
                self.assertFalse(self.marker.exists())
                self.manifest["signing"][field] = prior
        raw = json.dumps(self.manifest).replace(
            '"schema": 1', '"schema": 1, "schema": 1'
        )
        self.sign(raw)
        self.assertNotEqual(self.execute().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_signature_failure_never_executes_installer(self):
        self.sign()
        (self.path / "release-manifest.sig").write_bytes(bytes(64))
        self.assertNotEqual(self.execute().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_initialized_or_interrupted_policy_is_not_bypassed(self):
        for name in ("publisher-trust.json", "release-trust.initialized", "slsmassnotifyserver.active.json"):
            with self.subTest(name=name):
                trust = self.path / name
                trust.write_text("preserved")
                fixture = self.path / "fixture.sh"
                fixture.write_text(
                    BOOTSTRAP.read_text().replace(
                        "/var/lib/sls-mass-notify-trust", str(self.path)
                    )
                )
                command = 'source "$1"; fixture_marker="$3"; bootstrap_download(){ touch "$fixture_marker"; }; bootstrap_main 0.1.9-beta'
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        command,
                        "fixture",
                        str(fixture),
                        "unused",
                        str(self.marker),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("trust policy", result.stderr)
                self.assertFalse(self.marker.exists())
                trust.unlink()

    def test_profile_and_inspection_flags_are_forwarded_without_weakening_recovery(self):
        trust = self.path / 'empty-trust'
        fixture = self.path / 'bootstrap-fixture.sh'
        fixture.write_text(BOOTSTRAP.read_text().replace(
            '/var/lib/sls-mass-notify-trust', str(trust)))
        marker = self.path / 'arguments'
        command = r'''
source "$1"
bootstrap_download(){
  printf '#!/bin/bash\nprintf "%%s\\n" "$@" >"%s"\n' "$MARKER" >"$1/install_release.sh"
  chmod 0700 "$1/install_release.sh"
}
bootstrap_verify(){ :; }
bootstrap_main 0.1.9-beta --lite --inspect
'''
        result = subprocess.run(['bash', '-c', command, 'fixture', str(fixture)],
            env={**os.environ, 'MARKER': str(marker)}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker.read_text().splitlines(), ['--lite', '--inspect'])
        transaction='/var/lib/sls-mass-notify-installer/transaction-'+'a'*24
        evidence='/root/pre upgrade/phone-admission.json'
        recovering=command.replace('bootstrap_main 0.1.9-beta --lite --inspect',
            'bootstrap_main 0.1.9-beta --recover '+transaction+' --history-evidence "$EVIDENCE"')
        result=subprocess.run(['bash','-c',recovering,'fixture',str(fixture)],
            env={**os.environ,'MARKER':str(marker),'EVIDENCE':evidence},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(marker.read_text().splitlines(),['--recover',transaction,'--history-evidence',evidence])
        invalid = subprocess.run(
            ['bash', '-c', 'source "$1"; bootstrap_main 0.1.9-beta --standard --recover /var/lib/sls-mass-notify-installer/transaction-' + 'a' * 24,
             'fixture', str(fixture)], capture_output=True, text=True, timeout=10)
        self.assertEqual(invalid.returncode, 2)


if __name__ == "__main__":
    unittest.main()
