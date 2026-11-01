#!/usr/bin/python3
"""Exercise the standalone pre-execution verifier with a private ephemeral key."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

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
        for name in ("publisher-trust.json", "release-trust.initialized"):
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
