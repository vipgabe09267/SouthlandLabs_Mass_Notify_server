#!/usr/bin/python3
"""Exercise offline resolution with real pip on an externally managed Python.

The inert wheels contain only metadata and a module that must never be imported.
All subprocesses run inside the official disposable fixture namespace.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or os.environ.get(
    'SLS_TEST_PARENT_NET_NS'
) in (None, '', os.readlink('/proc/self/ns/net')):
    raise SystemExit('Use the private fixture runner; no pip process was started.')

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('offline_pep668_fixture', ROOT / 'tools/prepare_offline_install.py')
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)
NATIVE_PIP = ['/usr/bin/python3', '-I', '-m', 'pip', '--isolated', 'install',
              '--dry-run', '--ignore-installed', '--only-binary=:all:',
              '--require-hashes', '--no-input', '--no-index']


class OfflineNativeResolution(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sls-offline-native-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wheels = self.root / 'wheels'
        self.wheels.mkdir()
        self.first = self.wheel('slsofflinefirst')
        self.second = self.wheel('slsofflinesecond', requires='slsofflinefirst==1.0')
        self.contents = {
            'bin/sls_mass_notify/piper-packaging.lock': self.lock(self.first),
            'bin/sls_mass_notify/piper-requirements.lock': self.lock(self.first, self.second),
        }

    def wheel(self, name, requires=None):
        path = self.wheels / (name + '-1.0-py3-none-any.whl')
        metadata = 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n'
        if requires:
            metadata += 'Requires-Dist: ' + requires + '\n'
        metadata += '\n'
        dist = name + '-1.0.dist-info/'
        files = {
            name + '.py': b'raise RuntimeError("Offline validation must not import wheel code")\n',
            dist + 'METADATA': metadata.encode(),
            dist + 'WHEEL': b'Wheel-Version: 1.0\nGenerator: inert-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        }
        files[dist + 'RECORD'] = ''.join(filename + ',,\n' for filename in files).encode()
        with zipfile.ZipFile(path, 'w') as archive:
            for filename, body in files.items():
                archive.writestr(filename, body)
        return path

    @staticmethod
    def lock(*wheels):
        return ''.join(path.name.split('-')[0] + '==1.0 --hash=sha256:' +
                       hashlib.sha256(path.read_bytes()).hexdigest() + '\n'
                       for path in wheels).encode()

    def command(self, contents=None, target=None):
        lock = self.root / 'control.lock'
        lock.write_bytes(self.contents['bin/sls_mass_notify/piper-requirements.lock']
                         if contents is None else contents)
        command = NATIVE_PIP + ['--find-links', str(self.wheels), '-r', str(lock)]
        if target is not None:
            command += ['--target', str(target)]
        return subprocess.run(command, capture_output=True, text=True, timeout=30)

    def test_native_global_dry_run_exposes_externally_managed_refusal(self):
        marker = subprocess.run(['/usr/bin/python3', '-I', '-c',
            'import pathlib,sysconfig; print(pathlib.Path(sysconfig.get_path("stdlib"))/"EXTERNALLY-MANAGED")'],
            check=True, capture_output=True, text=True, timeout=5).stdout.strip()
        if not Path(marker).is_file():
            self.skipTest('Native interpreter does not have an externally managed marker.')
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('externally-managed-environment', result.stderr)

    def test_native_private_target_control_resolves_without_installing(self):
        target = self.root / 'unused-target'
        result = self.command(target=target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Would install', result.stdout)
        self.assertFalse(target.exists(), 'A dry run must not install wheel contents.')

    def test_offline_helper_resolves_both_locks_without_installation_or_residue(self):
        real_directory = tempfile.TemporaryDirectory
        observations = []

        class TrackedDirectory:
            def __enter__(inner):
                inner.context = real_directory(prefix='sls-offline-wheels-', dir=self.root)
                inner.path = Path(inner.context.__enter__())
                return str(inner.path)

            def __exit__(inner, *args):
                observations.append((inner.path, [p.relative_to(inner.path).as_posix()
                                     for p in inner.path.rglob('*')]))
                return inner.context.__exit__(*args)

        with patch.object(BUNDLE.tempfile, 'TemporaryDirectory', side_effect=lambda **unused: TrackedDirectory()):
            try:
                BUNDLE.verify_wheel_resolution(self.wheels, self.contents)
            except ValueError as error:
                self.fail('A complete offline wheelhouse must resolve with native pip: ' + str(error))
        self.assertEqual(len(observations), 1)
        path, entries = observations[0]
        self.assertEqual(set(entries), {'piper-packaging.lock', 'piper-requirements.lock'})
        self.assertFalse(path.exists())

    def test_missing_second_lock_wheel_is_refused(self):
        self.second.unlink()
        with self.assertRaisesRegex(ValueError, 'piper-requirements.lock'):
            BUNDLE.verify_wheel_resolution(self.wheels, self.contents)

    def test_second_lock_hash_mismatch_is_refused(self):
        self.contents['bin/sls_mass_notify/piper-requirements.lock'] = (
            b'slsofflinesecond==1.0 --hash=sha256:' + b'0' * 64 + b'\n')
        result = self.command(contents=self.contents['bin/sls_mass_notify/piper-requirements.lock'],
                              target=self.root / 'hash-control')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DO NOT MATCH THE HASHES', result.stderr)
        with self.assertRaisesRegex(ValueError, 'piper-requirements.lock'):
            BUNDLE.verify_wheel_resolution(self.wheels, self.contents)

    def test_corrupt_wheel_with_updated_hash_is_refused(self):
        self.second.write_bytes(b'invalid wheel archive')
        self.contents['bin/sls_mass_notify/piper-requirements.lock'] = self.lock(self.first, self.second)
        with self.assertRaisesRegex(ValueError, 'piper-requirements.lock'):
            BUNDLE.verify_wheel_resolution(self.wheels, self.contents)

    def test_unsatisfied_transitive_dependency_is_refused(self):
        self.second = self.wheel('slsofflinesecond', requires='slsofflinefirst==2.0')
        self.contents['bin/sls_mass_notify/piper-requirements.lock'] = self.lock(self.first, self.second)
        with self.assertRaisesRegex(ValueError, 'piper-requirements.lock'):
            BUNDLE.verify_wheel_resolution(self.wheels, self.contents)


def configured_authenticated_bundle_end_to_end():
    """Optional qualification input; the ordinary suite has no external assets."""
    directory = Path(os.environ['SLS_OFFLINE_BUNDLE_FIXTURE'])
    framework = os.environ['SLS_OFFLINE_BUNDLE_FRAMEWORK']
    dashboard = os.environ['SLS_OFFLINE_BUNDLE_DASHBOARD']
    result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'tools/prepare_offline_install.py'),
        str(directory), '--framework-version', framework, '--dashboard-version', dashboard],
        capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise AssertionError('Authenticated offline bundle validation failed: ' + result.stdout + result.stderr)
    report = json.loads(result.stdout)
    for field in ('ok', 'wheel_resolution_verified', 'upstream_signatures_verified', 'target_requirements_complete'):
        if report.get(field) is not True:
            raise AssertionError('Authenticated offline bundle did not verify ' + field)
    if report['target_upstream_versions_verified'] != {'framework': framework, 'dashboard': dashboard}:
        raise AssertionError('Authenticated offline bundle verified different target identities')
    print('AUTHENTICATED_OFFLINE_BUNDLE ' + json.dumps(report, sort_keys=True), flush=True)


def load_tests(loader, tests, pattern):
    # A separately supplied genuine signed candidate exercises the entire public
    # CLI, including publisher verification and upstream GPG, in this namespace.
    if os.environ.get('SLS_OFFLINE_BUNDLE_FIXTURE'):
        tests.addTest(unittest.FunctionTestCase(configured_authenticated_bundle_end_to_end))
    return tests


if __name__ == '__main__':
    unittest.main()
