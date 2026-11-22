#!/usr/bin/python3
"""Only the live lock owner may derive and publish configuration recovery."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import shutil
import subprocess
import sys
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


fixture_module = load('keeper_mfa_fixture', ROOT / 'tools/test_installer_mfa_recovery.py')
transaction = load('keeper_transaction', HELPERS / 'sls_install_transaction.py')
PAUSED_KEEPER = r'''
import importlib.util,os,pathlib,sys,time
spec=importlib.util.spec_from_file_location('actual_guard',sys.argv[1])
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
replace=os.replace
def pause_live_publish(source,target,*args,**kwargs):
    if target=='mass-notifications.config':
        pathlib.Path(sys.argv[3]).write_text('lock-owner-before-live-publish')
        while True:time.sleep(.01)
    return replace(source,target,*args,**kwargs)
os.replace=pause_live_publish
guard.hold(sys.argv[2],timeout=3,settings=True)
'''


class KeeperOwnedConfiguration(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.MfaRecoveryIntegration(methodName='test_actual_totp_login_is_accepted_by_recovery')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        original = self.fixture.original_snapshots['config.snapshot']
        candidate = self.fixture.settings()['active']
        candidate['unrelated_active']['number'] = 8
        after = self.fixture.crypto.encode_config(candidate)
        transaction.record_configuration_intent(self.fixture.transaction / 'recovery',
            hashlib.sha256(original).hexdigest(), original, after)
        self.fixture.crypto._atomic_write(self.fixture.data / 'mass-notifications.config', after, 0, 0)
        self.consumed = self.fixture.run_php('login')
        self.assertTrue(self.consumed['accepted'])
        self.advanced = self.fixture.settings()

    def request(self):
        fixture = self.fixture
        arguments = [str(fixture.transaction / 'recovery'),
            hashlib.sha256(fixture.original_snapshots['config.snapshot']).hexdigest(),
            str(fixture.transaction / 'config.snapshot'), str(fixture.data / 'mass-notifications.config'),
            'present', hashlib.sha256(fixture.original_snapshots['pending.snapshot']).hexdigest(),
            str(fixture.transaction / 'pending.snapshot'), str(fixture.data / 'mass-notifications.pending.config')]
        return ('restore-settings ' + json.dumps(arguments, separators=(',', ':')) + '\n').encode()

    def transform_request(self, action):
        # This models an installer baseline captured after all earlier logins,
        # before its first transform, with no staged configuration.
        settings = self.fixture.settings()['active']
        settings['mail_from_name'] = 'SLS Mass Notification System'
        settings['deployment_profile'] = 'standard'
        body = self.fixture.crypto.encode_config(settings)
        self.fixture.crypto._atomic_write(self.fixture.data / 'mass-notifications.config', body, 0, 0)
        (self.fixture.data / 'mass-notifications.pending.config').unlink()
        shutil.rmtree(self.fixture.transaction / 'recovery')
        (self.fixture.transaction / 'recovery').mkdir(mode=0o700)
        original_hash = hashlib.sha256(body).hexdigest()
        arguments = [action, str(self.fixture.data / 'mass-notifications.config'),
                     'lite' if action == 'profile' else '', 'absent',
                     str(self.fixture.transaction / 'recovery'), original_hash]
        return ('transform-settings ' + json.dumps(arguments, separators=(',', ':')) + '\n').encode()

    def start(self, pause=False):
        marker = self.fixture.root / 'paused-publish'
        command = ([sys.executable, '-I', '-c', PAUSED_KEEPER,
                    str(HELPERS / 'sls_install_guard.py'), str(self.fixture.data), str(marker)] if pause else
                   [sys.executable, '-I', str(HELPERS / 'sls_install_guard.py'), '--data', str(self.fixture.data),
                    '--settings', '--timeout', '3', 'hold'])
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        self.assertTrue(select.select([process.stdout], [], [], 5)[0])
        self.assertEqual(process.stdout.readline(), b'ready\n')
        return process, marker

    @staticmethod
    def stop(process):
        if process.poll() is None: process.kill()
        process.communicate(timeout=5)

    def test_keeper_restores_intended_settings_while_preserving_highest_consumed_counter(self):
        process, _ = self.start()
        process.stdin.write(self.request()); process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 8)[0])
        response = process.stdout.readline()
        self.assertTrue(response.startswith(b'restored-settings '), response)
        targets = json.loads(response.removeprefix(b'restored-settings '))
        self.assertEqual(targets['active_sha256'], hashlib.sha256(
            (self.fixture.data / 'mass-notifications.config').read_bytes()).hexdigest())
        current = self.fixture.settings()
        self.assertEqual(current['active']['unrelated_active']['number'], 7)
        for label in ('active', 'pending'):
            self.assertEqual(current[label]['operator_access'], self.advanced[label]['operator_access'])
            self.assertEqual(current[label]['immediate_config_revisions']['operator_access'],
                             self.advanced[label]['immediate_config_revisions']['operator_access'])
        process.stdin.write(b'release\n'); process.stdin.flush()
        _, stderr = process.communicate(timeout=5); self.assertEqual(process.returncode, 0, stderr)
        self.assertFalse(self.fixture.run_php('login', self.consumed['code'])['accepted'])

    def test_killing_lock_owner_before_publish_leaves_no_surviving_stale_writer(self):
        process, marker = self.start(pause=True)
        process.stdin.write(self.request()); process.stdin.flush()
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(marker.exists(), 'keeper did not reach its own protected configuration publication')
        self.fixture.now += 30
        login = subprocess.Popen(['php', str(self.fixture.php), 'login'],
            env={**os.environ, 'FIXTURE_MFA_NOW': str(self.fixture.now),
                 'FIXTURE_MODULE': str(ROOT / 'slsmassnotifyserver'), 'FIXTURE_DATA': str(self.fixture.data)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop, login)
        time.sleep(.1); self.assertIsNone(login.poll(), 'MFA writer escaped the actual settings lease')
        process.kill(); process.communicate(timeout=5)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        stdout, stderr = login.communicate(timeout=10)
        self.assertEqual(login.returncode, 0, stderr)
        consumed = json.loads(stdout); self.assertTrue(consumed['accepted'])
        current = self.fixture.settings()
        self.assertEqual(current['active']['unrelated_active']['number'], 8)
        for label in ('active', 'pending'):
            self.assertEqual(current[label]['operator_access']['accounts'][0]['auth']['totp_last_counter'], consumed['counter'])
        self.assertFalse(self.fixture.run_php('login', consumed['code'])['accepted'])

    def test_factory_label_transform_runs_inside_owner_without_changing_mfa(self):
        request = self.transform_request('branding')
        process, _ = self.start()
        process.stdin.write(request); process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 8)[0])
        response = process.stdout.readline()
        self.assertTrue(response.startswith(b'transformed-settings '), response)
        current = self.fixture.crypto.read_config(self.fixture.data / 'mass-notifications.config')
        self.assertEqual(current['mail_from_name'], 'SLL Mass Notify Server')
        self.assertEqual(current['operator_access'], self.advanced['active']['operator_access'])

    def test_transform_preserves_unresolved_immediate_settings_transaction(self):
        request = self.transform_request('branding')
        marker = self.fixture.data / '.sls-immediate-settings-transaction.json'
        marker.write_text('{"preserve":"unresolved immediate settings evidence"}')
        marker.chmod(0o600)
        before = (self.fixture.data / 'mass-notifications.config').read_bytes()
        process, _ = self.start()
        process.stdin.write(request); process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 8)[0])
        self.assertFalse(process.stdout.readline().startswith(b'transformed-settings '))
        self.assertEqual((self.fixture.data / 'mass-notifications.config').read_bytes(), before)
        self.assertFalse((self.fixture.data / 'mass-notifications.pending.config').exists())
        self.assertEqual(marker.read_text(), '{"preserve":"unresolved immediate settings evidence"}')

    def test_profile_transform_dies_with_owner_before_stale_publication(self):
        request = self.transform_request('profile')
        process, marker = self.start(pause=True)
        process.stdin.write(request); process.stdin.flush()
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(marker.exists(), 'profile did not execute inside its actual lease owner')
        self.fixture.now += 30
        login = subprocess.Popen(['php', str(self.fixture.php), 'login'],
            env={**os.environ, 'FIXTURE_MFA_NOW': str(self.fixture.now),
                 'FIXTURE_MODULE': str(ROOT / 'slsmassnotifyserver'), 'FIXTURE_DATA': str(self.fixture.data)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop, login)
        time.sleep(.1); self.assertIsNone(login.poll())
        process.kill(); process.communicate(timeout=5)
        stdout, stderr = login.communicate(timeout=10)
        self.assertEqual(login.returncode, 0, stderr)
        consumed = json.loads(stdout); self.assertTrue(consumed['accepted'])
        current = self.fixture.crypto.read_config(self.fixture.data / 'mass-notifications.config')
        self.assertEqual(current['deployment_profile'], 'standard')
        self.assertEqual(current['operator_access']['accounts'][0]['auth']['totp_last_counter'], consumed['counter'])
        self.assertFalse(self.fixture.run_php('login', consumed['code'])['accepted'])


if __name__ == '__main__':
    unittest.main()
