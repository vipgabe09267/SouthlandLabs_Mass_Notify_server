#!/usr/bin/env python3
"""Signer storage admission controls, executed only in isolated fixture namespaces."""
from pathlib import Path
import json
import os
import pwd
import signal
import stat
import time
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / 'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh'

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')


class SignerStorageAdmission(unittest.TestCase):
    def storage(self):
        source = SIGNER.read_text()
        match = re.search(r"<<'PYSIGN_STORAGE_PY'\n(.*?)\nPYSIGN_STORAGE_PY", source, re.S)
        self.assertIsNotNone(match, 'Bounded first-write signer storage admission is missing')
        namespace = {'__name__': 'isolated_signer_storage_fixture'}
        exec(compile(match.group(1), str(SIGNER) + ':storage', 'exec'), namespace)
        return namespace

    def row(self, device, available_bytes=1024 * 1024, available_inodes=100, read_only=False):
        return {'device': device, 'allocation_unit': 4096, 'available_bytes': available_bytes,
                'available_inodes': available_inodes, 'read_only': read_only}

    def role(self, name, path, amount=4096, inodes=1):
        return {'name': name, 'path': path, 'bytes': amount, 'inodes': inodes}

    def test_fixed_fresh_RSA3072_producer_has_bounded_metadata_growth(self):
        # Real GPG, temporary local keys only. Inspect metadata, never key bodies.
        with tempfile.TemporaryDirectory(prefix='signcap-') as name:
            root = Path(name); home = root / 'private'; native = root / 'native'
            home.mkdir(mode=0o700); native.mkdir(mode=0o700)
            environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(root)}
            peak = {'logical_bytes': 0, 'entries': 0}
            def observe():
                total = entries = 0
                for directory in (home, native):
                    for parent, dirs, files in os.walk(directory, followlinks=False):
                        for leaf in (*dirs, *files):
                            try: metadata = (Path(parent) / leaf).lstat()
                            except FileNotFoundError: continue
                            entries += 1
                            if stat.S_ISREG(metadata.st_mode): total += metadata.st_size
                peak['logical_bytes'] = max(peak['logical_bytes'], total)
                peak['entries'] = max(peak['entries'], entries)
            def command(arguments, payload=None):
                process = subprocess.Popen(arguments, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
                try:
                    if payload is not None: process.stdin.write(payload); process.stdin.close()
                    deadline = time.monotonic() + 120
                    while process.poll() is None:
                        observe()
                        if time.monotonic() > deadline: raise subprocess.TimeoutExpired(arguments, 120)
                        time.sleep(0.005)
                    output = process.stdout.read(65537); process.stdout.close(); observe()
                    self.assertEqual(process.returncode, 0, 'Disposable local GPG operation failed')
                    self.assertLessEqual(len(output), 65536)
                    return output
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL); process.wait()
            prefix = ['/usr/bin/gpg', '--no-options', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '']
            hostname = 'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 61
            parameters = ('Key-Type: RSA\nKey-Length: 3072\nName-Real: SLL Mass Notify Servers Local Signing\n'
                'Name-Email: root@' + hostname + '\nExpire-Date: 0\n%no-protection\n%commit\n').encode()
            try:
                command(prefix + ['--homedir', str(home), '--generate-key'], parameters)
                public = command(prefix + ['--homedir', str(home), '--armor', '--export'])
                self.assertGreater(len(public), 0)
                command(prefix + ['--homedir', str(native), '--import'], public)
                # A declared small fresh-key profile must be checked against real
                # GnuPG output; it is not a substitute for measured old DB copies.
                self.assertLessEqual(peak['logical_bytes'], 65536)
                self.assertLessEqual(peak['entries'], 48)
                print('SLL isolated GPG metadata profile: ' + json.dumps(peak, sort_keys=True))
            finally:
                for directory in (home, native):
                    subprocess.run(['/usr/bin/gpgconf', '--homedir', str(directory), '--kill', 'all'],
                        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=10, check=False)

    def test_signature_target_cannot_borrow_free_space_from_temporary_filesystem(self):
        api = self.storage()
        roles = [self.role('work', '/tmp', 8192), self.role('publication', '/module', 4096)]
        observed = {'/tmp': self.row(10), '/module': self.row(20, available_bytes=0)}
        with self.assertRaisesRegex(ValueError, 'space|bytes|capacity'):
            api['admit_roles'](roles, observe=lambda path: observed[path])

    def test_shared_filesystem_roles_require_their_combined_allocation(self):
        api = self.storage()
        roles = [self.role('work', '/tmp', 8192), self.role('publication', '/module', 8192)]
        with self.assertRaisesRegex(ValueError, 'space|bytes|capacity'):
            api['admit_roles'](roles, observe=lambda path: self.row(10, available_bytes=12288))
        result = api['admit_roles'](roles, observe=lambda path: self.row(10, available_bytes=16384))
        self.assertTrue(result['admitted'])
        self.assertEqual(len(result['filesystems']), 1)
        self.assertEqual(result['filesystems'][0]['required_bytes'], 16384)

    def test_fixed_inode_shortage_and_read_only_filesystem_fail(self):
        api = self.storage()
        roles = [self.role('private_keys', '/private', 4096, 2)]
        for observation in (self.row(10, available_inodes=1), self.row(10, read_only=True)):
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                api['admit_roles'](roles, observe=lambda path: observation)

    def test_explicit_dynamic_inode_table_keeps_byte_and_read_only_guards(self):
        api = self.storage()
        roles = [self.role('private_keys', '/private', 4096, 200)]
        result = api['admit_roles'](roles, observe=lambda path: self.row(10, available_inodes=None))
        self.assertTrue(result['admitted'])
        with self.assertRaises(ValueError):
            api['admit_roles'](roles, observe=lambda path: self.row(10, available_bytes=0, available_inodes=None))

    def test_unknown_or_boolean_capacity_counters_never_admit(self):
        api = self.storage()
        roles = [self.role('work', '/tmp')]
        for field, value in (('available_bytes', None), ('available_bytes', True),
                             ('available_inodes', False), ('allocation_unit', 0), ('read_only', None)):
            observation = self.row(10); observation[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                api['admit_roles'](roles, observe=lambda path: observation)

    def test_capacity_observation_never_follows_a_directory_alias_or_creates_missing_tree(self):
        api = self.storage()
        with tempfile.TemporaryDirectory(prefix='sll-signer-storage-fixture-') as name:
            root = Path(name); target = root / 'target'; target.mkdir()
            (root / 'alias').symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                api['observe_storage'](str(root / 'alias'))
            absent = root / 'not-created' / 'keyring'
            row = api['observe_storage'](str(absent))
            self.assertGreater(row['available_bytes'], 0)
            self.assertFalse(absent.exists())
            self.assertFalse(absent.parent.exists())

    def test_old_keybox_rewrite_uses_logical_size_without_reading_key_contents(self):
        api = self.storage()
        with tempfile.TemporaryDirectory() as name:
            home = Path(name) / 'ring'; home.mkdir()
            with (home / 'pubring.kbx').open('wb') as handle:
                handle.truncate(4 * 1024 * 1024)
            roles, logical = api['keyring_rewrite_roles']('native', str(home))
            self.assertGreaterEqual(logical, 4 * 1024 * 1024)
            self.assertGreaterEqual(sum(row['bytes'] for row in roles), logical)
            (home / 'redirect').symlink_to('/etc')
            with self.assertRaises(ValueError):
                api['keyring_rewrite_roles']('native', str(home))

    def test_actual_first_writes_and_publication_follow_their_capacity_checks(self):
        source = SIGNER.read_text()
        main = source.split('\nmain() {', 1)[1]
        self.assertLess(main.index('load_freepbx_metadata'), main.index('signer_storage prepare'))
        self.assertLess(main.index('signer_storage prepare'), main.index('WORKDIR="$(mktemp'))
        self.assertLess(main.index('signer_storage prepare'), main.index('prepare_signing_home'))
        lock = source.split('\nacquire_signing_lock() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(lock.index('signer_storage lock'), lock.index('parent.mkdir('))
        trust = source.split('\ntrust_signing_key_in_freepbx() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(trust.index('signer_storage import'), trust.index('prepare_freepbx_gpg_home'))
        publish = source.split('\npublish_candidate_transactionally() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(publish.index('signer_storage publish'), publish.index('signature_operation backup'))

    def test_native_php_discovery_never_opens_a_keyring_to_learn_its_location(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name); root.chmod(0o755)
            account = pwd.getpwnam('asterisk')
            marker = root / 'called'; marker.touch()
            os.chown(marker, account.pw_uid, account.pw_gid)
            source = SIGNER.read_text().replace('require "/etc/freepbx.conf";', '''
class FreePBX {
    static function Config() { return new self; }
    function get($name) { return ["AMPASTERISKWEBUSER"=>"asterisk",
        "AMPWEBROOT"=>"/var/www/html", "ASTSPOOLDIR"=>"/var/spool/asterisk"][$name]; }
    static function GPG() { file_put_contents(getenv("SLS_GPG_FIXTURE_CALLED"), "opened");
        throw new Exception("native getter may create a home or reject a restored owner"); }
}
''')
            script = root / 'fixture.sh'; script.write_text(source)
            workspace = root / 'workspace'; workspace.mkdir(mode=0o700)
            result = subprocess.run(['/bin/bash', '-c',
                'source "$1"; WORKDIR="$2"; load_freepbx_metadata; printf "%s" "$FREEPBX_GPG_HOME"',
                'fixture', str(script), str(workspace)], text=True, capture_output=True, timeout=8,
                env={**os.environ, 'SLS_GPG_FIXTURE_CALLED': str(marker)})
            self.assertEqual(marker.stat().st_size, 0, 'Discovery invoked the native keyring getter')
            self.assertEqual(result.returncode, 0, result.stderr)
            parent = account.pw_dir if os.path.isdir(account.pw_dir) else '/var/spool/asterisk'
            self.assertEqual(result.stdout, str(Path(parent) / '.gnupg'))

    def test_real_full_module_mount_refuses_before_private_key_or_workspace_creation(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            module = root / 'module'; module.mkdir()
            subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'size=4096', 'tmpfs', str(module)], check=True)
            try:
                (module / 'existing').write_bytes(b'a' * 4096)
                self.assertEqual(os.statvfs(module).f_bavail, 0)
                shell = r'''
source "$1"
MODULE=emptyspacefixture
LOCK_FILE="$2/sign.lock"
SIGN_HOME="$2/private"
validate_freepbx_metadata() { MODULE_DIR="$ROOT_FIXTURE/module"; }
approved_module_hashes() { printf 'example = %064d\n' 0; }
load_freepbx_metadata() { FREEPBX_GPG_HOME="$ROOT_FIXTURE/native"; }
main
'''
                result = subprocess.run(['/bin/bash', '-c', shell, 'fixture', str(SIGNER), str(root)],
                    env={**os.environ, 'ROOT_FIXTURE': str(root)}, capture_output=True, text=True, timeout=8)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('insufficient signing capacity for module signature', result.stderr)
                self.assertFalse((root / 'private').exists())
                self.assertFalse((root / 'native').exists())
                self.assertFalse(any(Path('/tmp').glob('emptyspacefixture-sls-local-sign.*')))
                self.assertEqual((module / 'existing').read_bytes(), b'a' * 4096)
            finally:
                subprocess.run(['/usr/bin/umount', str(module)], check=True)

    def test_only_key_import_requires_the_exported_public_key(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name); module = root / 'module'; module.mkdir()
            work = root / 'work'; work.mkdir()
            (work / 'module.sig.candidate').write_bytes(b'candidate fixture')
            shell = 'source "$1"; trap - EXIT; MODULE_DIR="$2/module"; WORKDIR="$2/work"; signer_storage "$3"'
            for stage, succeeds in [('publish', True), ('import', False)]:
                with self.subTest(stage=stage):
                    result = subprocess.run(['/bin/bash', '-c', shell, 'fixture', str(SIGNER), str(root), stage],
                        text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                    self.assertEqual(list(module.iterdir()), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
