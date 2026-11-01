#!/usr/bin/env python3
"""Isolated signed-installer profile conversion and rollback fixtures."""
import importlib.util
import hashlib
import shutil
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'tools/install_release.sh'
CRYPTO_SOURCE = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_config_crypto.py'


class LiteInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sls-lite-installer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bootstrap = self.root / 'bootstrap'
        self.bootstrap.mkdir(mode=0o700)
        self.keyring = self.root / 'keys/config-keys.json'
        self.helper = self.bootstrap / 'sls_config_crypto.py'
        self.helper.write_text(CRYPTO_SOURCE.read_text().replace(
            'KEYRING_PATH = Path("/etc/sls-mass-notify/config-keys.json")',
            'KEYRING_PATH = Path(' + repr(str(self.keyring)) + ')'))
        self.helper.chmod(0o700)
        spec = importlib.util.spec_from_file_location('sls_lite_crypto_fixture', self.helper)
        self.crypto = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.crypto)
        account = pwd.getpwnam('asterisk')
        self.uid, self.gid = account.pw_uid, account.pw_gid
        self.crypto.initialize_keyring(self.keyring, self.gid)
        shutil.copyfile(CRYPTO_SOURCE.parent / 'sls_install_transaction.py', self.bootstrap / 'sls_install_transaction.py')
        self.config = self.root / 'mass-notifications.config'

    def write_config(self, profile='standard', desktops=25, phones=25, queue=8):
        settings = {
            'deployment_profile': profile,
            'desktop_client_limit': desktops,
            'phone_device_limit': phones,
            'speech_synthesis_limit': 1,
            'speech_queue_limit': queue,
            'fixture_secret': 'preserved-value',
        }
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        return settings

    def run_conversion(self, option, pending='absent', guard='none', branding=False):
        self.recovery = Path(tempfile.mkdtemp(prefix='recovery-', dir=self.root))
        script = r'''
source "$1" "$2"
CONFIG_FILE="$3"
INSTALL_TEMP_ROOT="$4"
INSTALL_BOOTSTRAP_DIR="$5"
TRANSACTION_TOOL="$5/sls_install_transaction.py"; RECOVERY_DIR="$9"
LOG_FILE="$4/install.log"
PENDING_CONFIG_STATE="$6"
PENDING_CONFIG_PATH="$4/pending.config"
INSTALL_NOTIFICATION_SIDE_EFFECTS=0
snapshot_config
apply_requested_deployment_profile
if [ "$8" = 1 ]; then apply_factory_branding_defaults; fi
case "$7" in
  fail|recover)
    if [ "$7" = recover ]; then RECOVERY_REQUEST_MODE=1; fi
    INSTALL_BOOTSTRAP_DIR=""
    restore_freepbx_chown_permissions(){ return 0; }
    record_install_failure(){ :; }
    release_worker_coordination(){ :; }
    set +e
    false
    guard_config_on_exit
    ;;
  commit)
    INSTALL_BOOTSTRAP_DIR=""
    INSTALL_COMMITTED=1
    release_worker_coordination(){ :; }
    guard_config_on_exit
    ;;
esac
'''
        return subprocess.run(
            ['bash', '-c', script, 'fixture', str(INSTALLER), option,
             str(self.config), str(self.root), str(self.bootstrap), pending, guard, '1' if branding else '0', str(self.recovery)],
            capture_output=True, text=True, timeout=15,
        )


    def test_profile_and_branding_writes_have_private_durable_intentions(self):
        settings = self.write_config()
        settings['mail_from_name'] = 'SLS Mass Notification System'
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        original = self.config.read_bytes()
        result = self.run_conversion('--lite', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        evidence = self.recovery / 'configuration-intents.json'
        self.assertTrue(evidence.exists(), 'Settings changed without durable write intentions')
        value = json.loads(evidence.read_bytes())
        self.assertEqual(value['original_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(len(value['writes']), 2)
        self.assertEqual(value['writes'][0]['before_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(value['writes'][1]['before_sha256'], value['writes'][0]['after_sha256'])
        self.assertEqual(value['writes'][1]['after_sha256'], hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('preserved-value', evidence.read_text())


    def test_failed_intention_publication_never_changes_the_configuration(self):
        original = self.write_config()
        body = self.config.read_bytes()
        transaction = self.bootstrap / 'sls_install_transaction.py'
        with transaction.open('a') as output:
            output.write('\ndef atomic(path, value):\n    raise OSError("qualification durable evidence failure")\n')
        result = self.run_conversion('--lite')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), body)
        self.assertEqual(self.crypto.read_config(self.config), original)

    def test_later_recovery_accepts_its_own_recorded_configuration_write(self):
        original = self.write_config()
        result = self.run_conversion('--lite', guard='recover')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.crypto.read_config(self.config), original)

    def test_lite_and_standard_conversion_preserve_settings(self):
        self.write_config()
        result = self.run_conversion('--lite')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        settings = self.crypto.read_config(self.config)
        self.assertEqual(settings['deployment_profile'], 'lite')
        self.assertEqual(settings['speech_synthesis_limit'], 1)
        self.assertEqual(settings['speech_queue_limit'], 2)
        self.assertEqual(settings['fixture_secret'], 'preserved-value')
        result = self.run_conversion('--standard')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.crypto.read_config(self.config)['deployment_profile'], 'standard')

    def test_pending_settings_and_large_capacities_block_lite_before_write(self):
        for desktops, phones, pending in ((25, 25, 'present'), (26, 25, 'absent'), (25, 26, 'absent')):
            with self.subTest(desktops=desktops, phones=phones, pending=pending):
                settings = self.write_config(desktops=desktops, phones=phones)
                before = self.config.read_bytes()
                result = self.run_conversion('--lite', pending=pending)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.config.read_bytes(), before)
                self.assertEqual(self.crypto.read_config(self.config), settings)

    def test_failure_restores_original_and_commit_preserves_verified_profile(self):
        original = self.write_config()
        failed = self.run_conversion('--lite', guard='fail')
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.crypto.read_config(self.config), original)
        committed = self.run_conversion('--lite', guard='commit')
        self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
        self.assertEqual(self.crypto.read_config(self.config)['deployment_profile'], 'lite')

    def test_branding_migrates_only_exact_factory_defaults_and_is_idempotent(self):
        settings = self.write_config()
        settings.update({'mail_from_name': 'SLS Mass Notification System',
            'alert_email_subject': 'Southland Servers Group PBX: EAS alert triggered - {{event}}',
            'test_email_subject': 'Southland Servers Mass Notifications Server: NWS test triggered',
            'alert_email_body': 'Custom message mentioning Southland Servers must remain intact.'})
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        result = self.run_conversion('--standard', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(settings, mail_from_name='SLL Mass Notify Server',
            alert_email_subject='Southland Labs PBX: EAS alert triggered - {{event}}',
            test_email_subject='SLL Mass Notify Server: NWS test triggered')
        self.assertEqual(self.crypto.read_config(self.config), expected)
        before = self.config.read_bytes()
        result = self.run_conversion('--standard', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), before)

    def test_custom_branding_and_pending_settings_are_not_rewritten(self):
        settings = self.write_config()
        settings.update({'mail_from_name': 'Campus operations', 'alert_email_subject': 'Southland Servers custom alert',
            'test_email_subject': 'Custom test subject'})
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        before = self.config.read_bytes()
        result = self.run_conversion('--standard', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), before)
        settings['mail_from_name'] = 'SLS Mass Notification System'
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        before = self.config.read_bytes()
        result = self.run_conversion('--standard', pending='present', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_bytes(), before)

    def test_failed_install_restores_exact_pre_rebrand_configuration(self):
        settings = self.write_config()
        settings['mail_from_name'] = 'SLS Mass Notification System'
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        before = self.config.read_bytes()
        result = self.run_conversion('--standard', guard='fail', branding=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Factory sender and subject labels migrated', result.stdout)
        self.assertEqual(self.config.read_bytes(), before)

    def test_lite_conversion_and_branding_share_one_rollback_snapshot(self):
        settings = self.write_config()
        settings['mail_from_name'] = 'SLS Mass Notification System'
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        before = self.config.read_bytes()
        result = self.run_conversion('--lite', guard='fail', branding=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Factory sender and subject labels migrated', result.stdout)
        self.assertEqual(self.config.read_bytes(), before)
        result = self.run_conversion('--lite', guard='commit', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(settings, deployment_profile='lite', speech_queue_limit=2,
            mail_from_name='SLL Mass Notify Server')
        self.assertEqual(self.crypto.read_config(self.config), expected)

    def test_earlier_pbx_factory_test_subject_migrates_exactly(self):
        settings = self.write_config()
        settings['test_email_subject'] = 'Southland Servers Group PBX: NWS test triggered'
        settings['alert_email_subject'] = 'Campus custom alert for Southland Servers Group PBX'
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        result = self.run_conversion('--standard', branding=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(settings, test_email_subject='Southland Labs PBX: NWS test triggered')
        self.assertEqual(self.crypto.read_config(self.config), expected)

    def test_lite_conversion_refuses_active_enterprise_or_sso(self):
        for key in ('enterprise_labs', 'enterprise_identity'):
            with self.subTest(section=key):
                settings = self.write_config()
                settings[key] = {'enabled': True}
                self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
                before = self.config.read_bytes()
                result = self.run_conversion('--lite')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Enterprise', result.stderr)
                self.assertEqual(self.config.read_bytes(), before)

    def test_return_to_standard_keeps_stored_enterprise_inactive(self):
        settings = self.write_config(profile='lite', queue=2)
        settings.update({'enterprise_labs': {'enabled': True},
            'enterprise_identity': {'enabled': True, 'providers': [{'fixture_secret': 'retained'}]}})
        self.crypto._atomic_write(self.config, self.crypto.encode_config(settings), self.uid, self.gid)
        result = self.run_conversion('--standard')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(settings, deployment_profile='standard', enterprise_labs={'enabled': False},
            enterprise_identity={'enabled': False, 'providers': [{'fixture_secret': 'retained'}]})
        self.assertEqual(self.crypto.read_config(self.config), expected)


if __name__ == '__main__':
    unittest.main()
