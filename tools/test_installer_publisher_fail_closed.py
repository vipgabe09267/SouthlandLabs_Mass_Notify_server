#!/usr/bin/python3
"""Publisher rejection must stop conditional callers before any package helper runs.

This regression uses
only an inert package helper writing its effective UID in a disposable folder.
An explicit alternate archive hash is supplied: the default published-package
pin independently protects the ordinary unchanged online package.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or any(
    os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in
    (None, '', os.readlink('/proc/self/ns/' + kind))
    for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]
):
    raise SystemExit('Use the official private fixture runner; no application was invoked.')

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()
HELPERS = ('sls_module_trust.py sls_release_trust.py sls_privileged_install.py '
           'sls_installer_recovery.py sls_install_transaction.py sls_install_idle.py '
           'sls_install_guard.py sls_audio_state.py sls_config_crypto.py '
           'sls_upgrade_trust.py sls_legacy_permissions.py').split()


class PublisherFailClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print(json.dumps({'observation_scope': 'inert synthetic archive with an explicitly supplied alternative SHA256',
                          'qualification': 'Default published-package hash remains an independent protection; this fixture does not demonstrate a default online network bypass.'}), flush=True)

    def fixture(self, root):
        (root / 'freepbx.conf').write_text('inert inspection sentinel')
        framework = root / 'framework'
        framework.mkdir()
        (framework / 'module.xml').write_text('<module/>')
        installer = root / 'installer.sh'
        installer.write_text(SOURCE.replace('/etc/freepbx.conf', str(root / 'freepbx.conf'))
                             .replace('/var/www/html/admin/modules/framework', str(framework)))
        archive = root / 'inert-observation.tgz'
        version = ET.parse(ROOT / 'slsmassnotifyserver/module.xml').getroot().findtext('version')
        files = {'module.xml': ('<module><rawname>slsmassnotifyserver</rawname><version>' + version + '</version></module>').encode()}
        for helper in HELPERS:
            body = b'pass\n'
            if helper == 'sls_upgrade_trust.py':
                body = (b'import os, pathlib, sys\n'
                        b'pathlib.Path(os.environ["SLS_AUDIT_FINAL_MARKER"]).write_text(str(os.geteuid()))\n'
                        b'sys.exit(73)\n')
            files['bin/sls_mass_notify/' + helper] = body
        files['bin/sls_mass_notify/freepbx-mirror-signing.pub'] = b'inert unused key\n'
        with tarfile.open(archive, 'w:gz') as stream:
            for name, body in files.items():
                item = tarfile.TarInfo('slsmassnotifyserver/' + name)
                item.size = len(body)
                item.mode = 0o644
                stream.addfile(item, io.BytesIO(body))
        (root / 'release-manifest.json').write_text('{}\n')
        (root / 'release-manifest.sig').write_bytes(b'\0' * 64)
        return installer, archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def invoke(self, root, action):
        installer, archive, digest = self.fixture(root)
        harness = r'''
source "$1"
fixture="$2"; URL=""; TGZ="$3"; SHA256="$4"; INSTALL_TEMP_ROOT="$fixture"
SLS_MASS_NOTIFY_MANIFEST="$fixture/release-manifest.json"
SLS_MASS_NOTIFY_MANIFEST_SIGNATURE="$fixture/release-manifest.sig"
export SLS_AUDIT_FINAL_MARKER="$fixture/inert-helper-uid"
case "$5" in
  direct)
    download_tgz
    verify_tgz
    printf 'direct-unexpectedly-continued\n'
    ;;
  conditional)
    download_tgz
    if verify_tgz; then printf 'conditional-accepted\n'; else exit "$?"; fi
    ;;
  inspection)
    CONFIG_FILE="$fixture/absent-config"; SLS_MASS_NOTIFY_INVENTORY_ONLY=1
    bootstrap_resource_capacity() { printf '%s\n' '{"requirements":{},"deployment_profile":"standard","profile_selection":{"standard_memory_eligible":true,"lite_memory_eligible":false}}'; }
    select_install_temp_root() { INSTALL_TEMP_ROOT="$fixture"; }
    module_registry_state() { printf 'absent\n'; }
    inspect_installation
    ;;
esac
'''
        return subprocess.run(['bash', '-c', harness, 'fixture', str(installer), str(root), str(archive), digest, action],
                              text=True, capture_output=True, timeout=30)

    @staticmethod
    def diagnostics(root, result):
        marker = root / 'inert-helper-uid'
        return {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                'marker_present': marker.is_file(),
                'marker_contents': marker.read_text() if marker.is_file() else None,
                'private_inspection_logs': {path.name: path.read_text()[:262144]
                                            for path in root.glob('sls-mass-notify-inspection.*.log')}}

    def test_publisher_failure_stops_direct_and_conditional_callers(self):
        for action in ('direct', 'conditional'):
            with self.subTest(context=action), tempfile.TemporaryDirectory(dir='/run', prefix='sls-final-inspect-auth-') as directory:
                root = Path(directory)
                result = self.invoke(root, action)
                output = result.stdout + result.stderr
                self.assertIn('Publisher verification failed before activation:', output)
                self.assertFalse((root / 'inert-helper-uid').exists())
                if action == 'direct':
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertNotIn('direct-unexpectedly-continued', output)
                else:
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertNotIn('conditional-accepted', output)

    def test_inspection_never_executes_package_helper_after_publisher_rejection(self):
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-final-inspect-auth-') as directory:
            root = Path(directory)
            result = self.invoke(root, 'inspection')
            output = result.stdout + result.stderr
            observed = self.diagnostics(root, result)
            diagnostic = json.dumps(observed, sort_keys=True)
            print(json.dumps({'observation': 'inspection_inert_fixture_diagnostics', **observed}), flush=True)
            self.assertIn('Publisher verification failed before activation:', output, diagnostic)
            self.assertFalse((root / 'inert-helper-uid').exists(), diagnostic)
            # The actual preparation caller deliberately maps helper exit73 to1.
            self.assertEqual(result.returncode, 1, diagnostic)
            self.assertIn('Inspection failed.', output, diagnostic)
            self.assertEqual((root / 'freepbx.conf').read_text(), 'inert inspection sentinel')
            print(json.dumps({'observation': 'actual_inspection_after_rejected_publisher_signature',
                              'inert_package_helper_executed': False,
                              'outer_inspection_exit': result.returncode,
                              'explicit_alternative_archive_sha256': True,
                              'default_online_network_bypass_demonstrated': False}), flush=True)


if __name__ == '__main__':
    unittest.main()
