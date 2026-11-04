#!/usr/bin/python3
"""Signed old-to-new upgrade fixtures; no live PBX paths, network or services."""
import argparse
import importlib.util
import io
import json
import os
import pwd
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def package(path, name, contents):
    with tarfile.open(path, 'w:gz') as archive:
        for relative, body in contents.items():
            member = tarfile.TarInfo(name + '/' + relative)
            member.size = len(body)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(body))
    path.chmod(0o600)


class UpgradeTrustTests(unittest.TestCase):
    def test_previous_release_urls_preserve_legacy_and_current_tag_identities(self):
        self.assertEqual(self.upgrade.sls_release_url('0.1.8-beta','slsmassnotifyserver-0.1.8-beta.tgz'),'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/slsmassnotifyserver-0.1.8-beta/slsmassnotifyserver-0.1.8-beta.tgz')
        self.assertEqual(self.upgrade.sls_release_url('0.1.9-beta','release-manifest.json'),'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/release-0.1.9-beta/release-manifest.json')
        for version,name in (('../0.1.9','release-manifest.json'),('0.1.9-beta','slsmassnotifyserver-0.1.8-beta.tgz'),('0.1.9-beta','../key')):
            with self.subTest(version=version,name=name),self.assertRaises(self.upgrade.UpgradeError):
                self.upgrade.sls_release_url(version,name)

    def test_v_tag_upgrade_download_retains_bounds_and_canonical_package_name(self):
        url='https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/v0.1.9-beta/slsmassnotifyserver-0.1.9-beta.tgz'
        response=io.BytesIO(b'fixture');response.headers={'Content-Length':'7'}
        destination=self.root/'vtag-download.tgz'
        with patch.object(self.upgrade.urllib.request,'build_opener') as client:
            client.return_value.open.return_value=response
            self.upgrade.download(url,destination,16)
        self.assertEqual(destination.read_bytes(),b'fixture')

    def test_historical_uppercase_release_download_remains_allowed(self):
        url='https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/V0.1.9-beta/slsmassnotifyserver-0.1.9-beta.tgz'
        response=io.BytesIO(b'historical signed input');response.headers={'Content-Length':'23'}
        destination=self.root/'historical-uppercase.tgz'
        with patch.object(self.upgrade.urllib.request,'build_opener') as client:
            client.return_value.open.return_value=response
            self.upgrade.download(url,destination,64)
        self.assertEqual(destination.read_bytes(),b'historical signed input')

    def test_exact_release_alias_downloads_and_other_aliases_fail_before_network(self):
        prefix='https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'
        destination=self.root/'alias-download.tgz'
        response=io.BytesIO(b'fixture');response.headers={'Content-Length':'7'}
        with patch.object(self.upgrade.urllib.request,'build_opener') as client:
            client.return_value.open.return_value=response
            self.upgrade.download(prefix+'release-0.1.9-beta/slsmassnotifyserver-0.1.9-beta.tgz',destination,16)
        self.assertEqual(destination.read_bytes(),b'fixture')
        for relative in ('release-0.1.8-beta/release-manifest.json',
                         'release-0.1.10-beta/release-manifest.json',
                         'release-0.1.9/release-manifest.json',
                         'Release-0.1.9-beta/release-manifest.json',
                         'release-0.1.9-beta/slsmassnotifyserver-0.1.10-beta.tgz',
                         'release-0.1.9-beta/release-manifest.json?other=1'):
            with self.subTest(relative=relative),patch.object(self.upgrade.urllib.request,'build_opener') as client:
                with self.assertRaises(self.upgrade.UpgradeError):
                    self.upgrade.download(prefix+relative,self.root/'rejected-download',16)
                client.assert_not_called()

    def test_signed_stock_verifies_with_long_persistent_recovery_workspace(self):
        workspace=self.root/('persistent-recovery-'+'x'*100);workspace.mkdir(mode=0o700)
        expected={'module.xml':b'<module><rawname>framework</rawname><version>17.0.5</version></module>',
                  'fixture.txt':b'authenticated stock in long recovery workspace'}
        plain=self.root/'long-workspace.tgz';package(plain,'framework',expected)
        signed=self.root/'long-workspace.tgz.gpg'
        subprocess.run(self.gpg_command+['--output',str(signed),'--sign',str(plain)],check=True,capture_output=True,timeout=15)
        with patch.dict(os.environ,{'TMPDIR':'/tmp'}):
            contents,provenance=self.upgrade.upstream_contents(signed,'framework','17.0.5',workspace)
        self.assertEqual(contents,expected)
        self.assertEqual(provenance['upstream_signer'],self.upgrade.UPSTREAM_SIGNER)

    def upstream_with_output_observation(self, signed, limit, observed):
        real_run = self.upgrade.subprocess.run
        def observe(command, *args, **kwargs):
            completed = real_run(command, *args, **kwargs)
            if '--decrypt' in command:
                output = Path(command[command.index('--output') + 1])
                observed.append(output.stat().st_size if output.exists() else 0)
            return completed
        with patch.object(self.trust, 'MAX_ARCHIVE', limit), patch.object(self.upgrade.subprocess, 'run', side_effect=observe):
            return self.upgrade.upstream_contents(signed, 'framework', '17.0.5', self.root)

    def test_unsigned_compressed_plaintext_is_bounded_before_signature_rejection(self):
        plain = self.root / 'expanded.bin'
        plain.write_bytes(b'x' * (2 * 1024 * 1024))
        unsigned = self.root / 'unsigned-compressed.gpg'
        subprocess.run(self.gpg_command + ['--compress-algo', 'ZIP', '--output', str(unsigned), '--store', str(plain)], check=True, capture_output=True, timeout=15)
        limit = 64 * 1024
        self.assertLess(unsigned.stat().st_size, limit)
        observed = []
        before = set(Path('/tmp').glob('sls-upstream-gpg-*'))
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'signature is invalid'):
            self.upstream_with_output_observation(unsigned, limit, observed)
        self.assertTrue(observed)
        self.assertLessEqual(max(observed), limit, 'Unauthenticated GPG plaintext exceeded the admitted package bound before rejection.')
        self.assertEqual(set(Path('/tmp').glob('sls-upstream-gpg-*')), before)

    def test_signed_stock_at_plaintext_limit_remains_valid(self):
        plain = self.root / 'boundary.tgz'
        expected = {'module.xml': b'<module><rawname>framework</rawname><version>17.0.5</version></module>', 'fixture.txt': b'authenticated stock'}
        package(plain, 'framework', expected)
        limit = 64 * 1024
        # Gzip permits trailing zero padding. Preserve a real, valid package
        # while exercising the exact GPG plaintext-output boundary.
        self.assertLess(plain.stat().st_size, limit)
        with plain.open('ab') as output:
            output.write(b'\0' * (limit - plain.stat().st_size))
        signed = self.root / 'boundary.tgz.gpg'
        subprocess.run(self.gpg_command + ['--output', str(signed), '--sign', str(plain)], check=True, capture_output=True, timeout=15)
        observed = []
        before = set(Path('/tmp').glob('sls-upstream-gpg-*'))
        contents, provenance = self.upstream_with_output_observation(signed, limit, observed)
        self.assertEqual(contents, expected)
        self.assertEqual(provenance['upstream_signer'], self.upgrade.UPSTREAM_SIGNER)
        self.assertEqual(observed, [limit])
        self.assertEqual(set(Path('/tmp').glob('sls-upstream-gpg-*')), before)

    def test_installed_identity_rejects_multibyte_document_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            web=Path(temporary);path=web/'admin/modules/slsmassnotifyserver/module.xml'
            path.parent.mkdir(parents=True)
            for encoding in ('utf-8', 'utf-16', 'utf-16-le', 'utf-16-be'):
                xml_encoding={'utf-16-le':'UTF-16LE', 'utf-16-be':'UTF-16BE'}.get(encoding,encoding)
                for declaration in ('', '<!DOCTYPE module [<!ENTITY version "0.1.8-beta">]>'):
                    with self.subTest(encoding=encoding, declaration=bool(declaration)):
                        version='&version;' if declaration else '0.1.8-beta'
                        path.write_bytes(('<?xml version="1.0" encoding="'+xml_encoding+'"?>'+declaration+'<module><rawname>slsmassnotifyserver</rawname><version>'+version+'</version></module>').encode(encoding))
                        if declaration:
                            with self.assertRaisesRegex(self.upgrade.UpgradeError,'Unsupported module XML declarations'):
                                self.upgrade.identity(web,'slsmassnotifyserver')
                        else:
                            self.assertEqual(self.upgrade.identity(web,'slsmassnotifyserver'),'0.1.8-beta')

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='sls-upgrade-signed-')
        cls.base = Path(cls.temporary.name)
        cls.helpers = cls.base / 'helpers'
        cls.helpers.mkdir(mode=0o700)
        for name in ('sls_upgrade_trust', 'sls_module_trust', 'sls_release_trust', 'sls_installer_recovery'):
            shutil.copyfile(BIN / (name + '.py'), cls.helpers / (name + '.py'))
        spec = importlib.util.spec_from_file_location('upgrade_fixture', cls.helpers / 'sls_upgrade_trust.py')
        cls.upgrade = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.upgrade)
        cls.trust = cls.upgrade.TRUST
        cls.key = cls.base / 'ed25519.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(cls.key)], check=True, capture_output=True)
        cls.trust.PUBLIC_KEY = subprocess.run(['openssl', 'pkey', '-in', str(cls.key), '-pubout'], check=True, capture_output=True).stdout
        cls.gpg = cls.base / 'gnupg'; cls.gpg.mkdir(mode=0o700)
        cls.gpg_command = ['gpg', '--no-options', '--homedir', str(cls.gpg), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
        subprocess.run(cls.gpg_command + ['--quick-generate-key', 'SLS upgrade fixture <fixture@example.invalid>', 'rsa2048', 'sign', '0'], check=True, capture_output=True, timeout=30)
        key = subprocess.run(cls.gpg_command + ['--armor', '--export'], check=True, capture_output=True).stdout
        (cls.helpers / 'freepbx-mirror-signing.pub').write_bytes(key)
        fingerprints = subprocess.run(cls.gpg_command + ['--with-colons', '--fingerprint'], check=True, capture_output=True, text=True).stdout
        cls.upgrade.UPSTREAM_SIGNER = next(line.split(':')[9] for line in fingerprints.splitlines() if line.startswith('fpr:'))
        cls.upgrade.UPSTREAM_KEY_SHA256 = cls.trust.digest(key)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf', '--homedir', str(cls.gpg), '--kill', 'gpg-agent'], capture_output=True, timeout=10)
        cls.temporary.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='case-', dir=self.base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fs = self.root / 'fs'; self.web = self.fs / 'var/www/html'
        self.offline = self.root / 'offline'; self.offline.mkdir(mode=0o700)
        self.stock = {}
        for module in ('dashboard', 'framework'):
            contents = {'module.xml': ('<module><rawname>' + module + '</rawname><version>17.0.5</version></module>').encode(), 'install.php': b'<?php // authenticated stock fixture\n'}
            if module == 'framework':
                contents.update({self.upgrade.MENU_NAME: b"<?php\n\telse if ($a == 'other')\n\t\treturn true;\n", self.upgrade.SPINNER: b'GIF89a fixture',
                                 'amp_conf/bin/fwconsole': b'installer-only mapping', 'upgrades/15.0/upgrade.php': b'installer-only upgrade', 'installlib/installer.class.php': b'installer only', 'install': b'installer only'})
            self.stock[module] = contents
            plain = self.root / (module + '.tgz'); package(plain, module, contents)
            subprocess.run(self.gpg_command + ['--output', str(self.offline / (module + '-17.0.5.tgz.gpg')), '--sign', str(plain)], check=True, capture_output=True, timeout=20)
            for name, body in contents.items():
                if module == 'framework' and not self.upgrade.deployed_framework(name): continue
                target = self.web / (name[16:] if module == 'framework' and name.startswith('amp_conf/htdocs/') else 'admin/modules/' + module + '/' + name)
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body)
        self.old = {'module.xml': b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.4-beta</version></module>',
                    'bin/sls_mass_notify_maintenance.sh': b'authenticated old maintenance\n', 'bin/sls_mass_notify_update.sh': b'authenticated old updater\n',
                    **{'dashboard/' + name: ('old widget ' + name).encode() for name in self.upgrade.WIDGETS}}
        self.new = {**self.old, 'module.xml': b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.5-beta</version></module>',
                    **{'dashboard/' + name: ('new widget ' + name).encode() for name in self.upgrade.WIDGETS}}
        self.previous = self.release('previous', '0.1.4-beta', self.old)
        self.candidate = self.release('candidate', '0.1.5-beta', self.new)
        for name, body in self.old.items():
            target = self.web / 'admin/modules/slsmassnotifyserver' / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body)
        for name in self.upgrade.WIDGETS:
            target = self.web / 'admin/modules/dashboard' / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.old['dashboard/' + name])
        menu = self.web / 'admin/views/menu_items.php'; menu.write_bytes(self.upgrade.menu_overlay(menu.read_bytes()))
        self.data = self.fs / 'var/lib/asterisk/SLS_Mass_Notifications_Plugin'; self.data.mkdir(parents=True)
        self.preserved = {'mass-notifications.config': b'active protected configuration', 'mass-notifications.pending.config': b'pending protected configuration', 'delivery-history.json': b'current delivery receipts'}
        for name, body in self.preserved.items(): (self.data / name).write_bytes(body)
        for name, digest in self.upgrade.runtime_files(self.old).items():
            body = self.old['bin/' + Path(name).name]
            target = self.fs / name[1:]; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body); target.chmod(0o755)
        self.cron = b'12 1 * * * /usr/bin/true\n* * * * * /usr/bin/timeout 900 /usr/local/bin/sls_mass_notify/sls_mass_notify_maintenance.sh\n17 */6 * * * /usr/bin/timeout 1800 /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh\n'
        self.original_root_approval = self.upgrade.previous_root_approval
        self.workspace = self.root / 'review'
        self.args = argparse.Namespace(workspace=self.workspace, trust_root=self.root / 'live-trust', archive=self.candidate[0], manifest=self.candidate[1], signature=self.candidate[2])
        self.environment = {'SLS_MASS_NOTIFY_UPSTREAM_PACKAGES': str(self.offline),
                            'SLS_MASS_NOTIFY_PREVIOUS_TGZ': str(self.previous[0]), 'SLS_MASS_NOTIFY_PREVIOUS_MANIFEST': str(self.previous[1]), 'SLS_MASS_NOTIFY_PREVIOUS_MANIFEST_SIGNATURE': str(self.previous[2])}

    def test_cron_runner_jobs_require_exact_fixed_commands_and_signed_source(self):
        contents={**self.old,'bin/sls_mass_notify/sls_cron_runner.py':b'authenticated fixed cron runner\n'}
        path=self.fs/(self.upgrade.RUNTIME+'/sls_cron_runner.py')[1:]
        path.write_bytes(contents['bin/sls_mass_notify/sls_cron_runner.py']);path.chmod(0o755)
        data={'version':'0.1.5-beta','source':{'archive_sha256':'a'*64}}
        jobs=b'* * * * * /usr/bin/python3 -I '+self.upgrade.RUNTIME.encode()+b'/sls_cron_runner.py maintenance >/dev/null 2>&1\n17 * * * * /usr/bin/python3 -I '+self.upgrade.RUNTIME.encode()+b'/sls_cron_runner.py update >/dev/null 2>&1\n'
        approved=self.original_root_approval(data,contents,prefix=self.fs,cron=jobs)
        self.assertEqual(len(approved['root_jobs']),2)
        self.assertIn(self.upgrade.RUNTIME+'/sls_cron_runner.py',approved['files'])
        for altered in (jobs.replace(b'maintenance ',b'weather ',1),jobs.replace(b' >/dev/null 2>&1',b'',1),jobs+b'* * * * * /bin/sh -c evil\n'+jobs.splitlines()[0]+b'\n'):
            with self.assertRaises(self.upgrade.UpgradeError): self.original_root_approval(data,contents,prefix=self.fs,cron=altered)
        path.unlink()
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'runner lacks'):
            self.original_root_approval(data,self.old,prefix=self.fs,cron=jobs)

    def test_previous_root_approval_preserves_comments_and_backup_operands(self):
        data={'version':'0.1.5-beta','source':{'archive_sha256':'a'*64}}
        unrelated=(b'# verify /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh\n'
                   b'0 2 * * * /usr/bin/sha256sum /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh\n'
                   b"0 2 * * * /usr/bin/echo ';' /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh\n")
        approved=self.original_root_approval(data,self.old,prefix=self.fs,cron=self.cron+unrelated)
        self.assertEqual(approved['root_jobs'],[line.decode() for line in self.cron.splitlines()[1:]])

    def test_previous_root_approval_reads_under_the_native_account_lock(self):
        recovery=self.upgrade.helper('sls_installer_recovery');active=[]
        @contextmanager
        def guard(accounts):
            self.assertEqual(accounts,('root',));active.append(True)
            try:yield
            finally:active.pop()
        def read(body=None,user='root'):
            self.assertTrue(active,'Upgrade read root cron without native FreePBX coordination')
            self.assertIsNone(body);self.assertEqual(user,'root');return self.cron
        data={'version':'0.1.5-beta','source':{'archive_sha256':'a'*64}}
        original_helper=self.upgrade.helper
        with patch.object(self.upgrade,'helper',side_effect=lambda name:recovery if name=='sls_installer_recovery' else original_helper(name)),patch.object(recovery,'native_cron_lock',guard),patch.object(recovery.Recovery,'system_cron',read):
            approved=self.original_root_approval(data,self.old,prefix=self.fs)
        self.assertEqual(len(approved['root_jobs']),2)

    def release(self, directory, version, contents, *, tag=None):
        root = self.root / directory; root.mkdir(mode=0o700)
        archive = root / ('slsmassnotifyserver-' + version + '.tgz'); package(archive, 'slsmassnotifyserver', contents)
        manifest = root / 'release-manifest.json'; signature = root / 'release-manifest.sig'
        manifest.write_text(json.dumps({'schema': 1, 'version': version, 'tag': tag or 'slsmassnotifyserver-' + version, 'package': archive.name, 'package_sha256': self.trust.digest(archive.read_bytes())}))
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key), '-in', str(manifest), '-out', str(signature)], check=True, capture_output=True)
        return archive, manifest, signature

    def prepare(self):
        with patch.object(self.upgrade, 'WEB', self.web), patch.dict(os.environ, self.environment, clear=True), patch.object(self.upgrade, 'previous_root_approval', side_effect=lambda data, contents: self.original_root_approval(data, contents, prefix=self.fs, cron=self.cron)):
            self.upgrade.prepare(self.args)

    def assert_preserved(self):
        for name, body in self.preserved.items(): self.assertEqual((self.data / name).read_bytes(), body)
        self.assertFalse(self.args.trust_root.exists())

    def rollback_fixture(self):
        self.prepare()
        backup = self.root / 'module-backup'
        backup.mkdir(mode=0o700)
        live = self.web / 'admin/modules/slsmassnotifyserver'
        live.rename(backup / 'slsmassnotifyserver')
        live.mkdir()
        for name, body in self.new.items():
            target = live / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return live, backup

    def restore_module(self, backup, existed=True):
        with patch.object(self.upgrade, 'WEB', self.web):
            self.upgrade.restore_previous_module(self.workspace, backup, existed)

    def test_module_rollback_can_resume_after_both_directory_moves(self):
        live, backup = self.rollback_fixture()
        self.restore_module(backup)
        self.assertEqual((live / 'module.xml').read_bytes(), self.old['module.xml'])
        failed = backup / 'failed-module'
        self.assertEqual((failed / 'module.xml').read_bytes(), self.new['module.xml'])
        identities = (live.stat().st_ino, failed.stat().st_ino)
        self.restore_module(backup)
        self.assertEqual((live.stat().st_ino, failed.stat().st_ino), identities)
        self.assert_preserved()

    def test_module_rollback_resumes_after_only_the_first_directory_move(self):
        live, backup = self.rollback_fixture()
        live.rename(backup / 'failed-module')
        self.restore_module(backup)
        self.assertEqual((live / 'module.xml').read_bytes(), self.old['module.xml'])
        self.assertEqual((backup / 'failed-module/module.xml').read_bytes(), self.new['module.xml'])
        self.assert_preserved()

    def test_private_module_backup_under_freepbx_owned_parent_can_be_restored(self):
        live, backup = self.rollback_fixture()
        actual = live.parent / '.sls-mass-notify-recovery.ABC123'
        backup.rename(actual)
        account = pwd.getpwnam('asterisk')
        os.chown(live.parent, account.pw_uid, account.pw_gid)
        live.parent.chmod(0o775)
        self.restore_module(actual)
        self.restore_module(actual)
        self.assertEqual((live / 'module.xml').read_bytes(), self.old['module.xml'])
        self.assertEqual((actual / 'failed-module/module.xml').read_bytes(), self.new['module.xml'])

    def native_backup_fixture(self):
        live, backup = self.rollback_fixture()
        actual = live.parent / '.sls-mass-notify-recovery.ABC123'; backup.rename(actual)
        account = pwd.getpwnam('asterisk')
        (actual/'module-swap-complete').write_bytes(b'')
        for item in [actual,*actual.rglob('*')]:
            os.chown(item,account.pw_uid,account.pw_gid)
            item.chmod(0o775 if item.is_dir() else 0o664)
        return live,actual

    def test_authenticated_legacy_backup_recovers_after_native_boot_permission_normalization(self):
        live,backup=self.native_backup_fixture()
        self.restore_module(backup)
        self.assertEqual((live/'module.xml').read_bytes(),self.old['module.xml'])
        self.assertEqual((backup/'failed-module/module.xml').read_bytes(),self.new['module.xml'])
        self.assertEqual((backup.stat().st_uid,backup.stat().st_gid,stat.S_IMODE(backup.stat().st_mode)),(0,0,0o700))
        self.restore_module(backup)
        self.assert_preserved()

    def test_modified_native_backup_is_not_adopted_or_moved(self):
        live,backup=self.native_backup_fixture()
        (backup/'slsmassnotifyserver/module.xml').write_bytes(b'changed after the signed approval')
        before=live.stat().st_ino,backup.stat().st_uid,stat.S_IMODE(backup.stat().st_mode)
        with self.assertRaises((self.upgrade.UpgradeError,self.trust.TrustError)):
            self.restore_module(backup)
        self.assertEqual((live.stat().st_ino,backup.stat().st_uid,stat.S_IMODE(backup.stat().st_mode)),before)
        self.assertFalse((backup/'failed-module').exists())

    def test_native_backup_unknown_entries_or_unsafe_markers_are_not_adopted(self):
        live,backup=self.native_backup_fixture();marker=backup/'module-swap-complete'
        for kind in ('unknown','nonempty-marker','linked-marker','world-write'):
            with self.subTest(kind=kind):
                marker.unlink(missing_ok=True);marker.write_bytes(b'');marker.chmod(0o664)
                account=pwd.getpwnam('asterisk');os.chown(marker,account.pw_uid,account.pw_gid)
                unknown=backup/'unknown';victim=self.root/('marker-victim-'+kind);victim.write_bytes(b'unchanged')
                if kind=='unknown':unknown.write_bytes(b'preserve')
                elif kind=='nonempty-marker':marker.write_bytes(b'unrecognized authority')
                elif kind=='linked-marker':marker.unlink();marker.symlink_to(victim)
                else:backup.chmod(0o777)
                before=live.stat().st_ino,backup.stat().st_uid,stat.S_IMODE(backup.stat().st_mode)
                with self.assertRaises((self.upgrade.UpgradeError,self.trust.TrustError,OSError)):
                    self.restore_module(backup)
                self.assertEqual((live.stat().st_ino,backup.stat().st_uid,stat.S_IMODE(backup.stat().st_mode)),before)
                self.assertEqual(victim.read_bytes(),b'unchanged')
                unknown.unlink(missing_ok=True);backup.chmod(0o775)

    def test_open_writer_cannot_change_legacy_backup_between_validation_and_restore(self):
        live,backup=self.native_backup_fixture();target=backup/'slsmassnotifyserver/module.xml'
        original_chown=os.fchown;changed=[]
        with target.open('r+b') as writer:
            def changed_chown(fd,uid,gid):
                result=original_chown(fd,uid,gid)
                if not changed and os.fstat(fd).st_ino==backup.stat().st_ino:
                    changed.append(True);writer.seek(0);writer.write(b'changed through an existing descriptor');writer.truncate();writer.flush()
                return result
            before=live.stat().st_ino
            with patch.object(self.upgrade.os,'fchown',side_effect=changed_chown):
                with self.assertRaises((self.upgrade.UpgradeError,self.trust.TrustError)):
                    self.restore_module(backup)
            self.assertEqual(live.stat().st_ino,before)
            self.assertFalse((backup/'failed-module').exists())
            self.assertTrue(changed,'The existing writer did not reach the sealing boundary')

    def test_module_rollback_resumes_after_durable_move_failure(self):
        live, backup = self.rollback_fixture()
        real_fsync = os.fsync
        failed = []
        def fsync(descriptor):
            if not failed:
                failed.append(True)
                raise OSError('fixture power loss after moving the failed module')
            return real_fsync(descriptor)
        with patch.object(self.upgrade.os, 'fsync', side_effect=fsync):
            with self.assertRaises(OSError):
                self.restore_module(backup)
        self.assertFalse(live.exists())
        self.assertTrue((backup / 'slsmassnotifyserver').exists())
        self.assertTrue((backup / 'failed-module').exists())
        self.restore_module(backup)
        self.assertEqual((live / 'module.xml').read_bytes(), self.old['module.xml'])
        self.assert_preserved()

    def test_unsafe_module_backup_is_never_moved_into_the_live_tree(self):
        live, backup = self.rollback_fixture()
        original = backup / 'slsmassnotifyserver'
        original.rename(backup / 'preserved-original')
        original.symlink_to(backup / 'preserved-original', target_is_directory=True)
        before = live.stat().st_ino
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unsafe module recovery tree'):
            self.restore_module(backup)
        self.assertEqual(live.stat().st_ino, before)
        self.assertFalse((backup / 'failed-module').exists())
        original.unlink()
        (backup / 'preserved-original').rename(original)
        account = pwd.getpwnam('asterisk')
        os.chown(backup, account.pw_uid, account.pw_gid)
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unsafe module recovery directory'):
            self.restore_module(backup)
        self.assertEqual(live.stat().st_ino, before)

    def test_module_rollback_does_not_replace_a_modified_backup(self):
        live, backup = self.rollback_fixture()
        target = backup / 'slsmassnotifyserver/module.xml'
        target.write_bytes(b'changed independently')
        before = live.stat().st_ino
        with self.assertRaises(self.trust.TrustError):
            self.restore_module(backup)
        self.assertEqual(live.stat().st_ino, before)
        self.assertFalse((backup / 'failed-module').exists())
        self.assertEqual(target.read_bytes(), b'changed independently')

    def test_repeated_rollback_does_not_approve_modified_restored_code(self):
        live, backup = self.rollback_fixture()
        self.restore_module(backup)
        target = live / 'module.xml'
        target.write_bytes(b'changed after rollback')
        failed = backup / 'failed-module'
        before = failed.stat().st_ino
        with self.assertRaises(self.trust.TrustError):
            self.restore_module(backup)
        self.assertEqual(target.read_bytes(), b'changed after rollback')
        self.assertEqual(failed.stat().st_ino, before)

    def test_ambiguous_second_rollback_preserves_all_three_trees(self):
        live, backup = self.rollback_fixture()
        failed = backup / 'failed-module'
        failed.mkdir()
        (failed / 'evidence').write_bytes(b'previous failed release')
        identities = (live.stat().st_ino, (backup / 'slsmassnotifyserver').stat().st_ino, failed.stat().st_ino)
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'ambiguous'):
            self.restore_module(backup)
        self.assertEqual(identities, (live.stat().st_ino, (backup / 'slsmassnotifyserver').stat().st_ino, failed.stat().st_ino))

    def test_fresh_failed_install_rollback_can_be_repeated(self):
        shutil.rmtree(self.web / 'admin/modules/slsmassnotifyserver')
        for name in self.upgrade.WIDGETS:
            (self.web / 'admin/modules/dashboard' / name).unlink()
        runtime = self.fs / self.upgrade.RUNTIME[1:]
        shutil.rmtree(runtime)
        self.cron = b'12 1 * * * /usr/bin/true\n'
        self.prepare()
        live = self.web / 'admin/modules/slsmassnotifyserver'
        live.mkdir()
        (live / 'payload').write_bytes(b'failed fresh install')
        backup = self.root / 'module-backup'
        backup.mkdir(mode=0o700)
        self.restore_module(backup, False)
        failed = backup / 'failed-module'
        before = failed.stat().st_ino
        self.restore_module(backup, False)
        self.assertFalse(live.exists())
        self.assertEqual(failed.stat().st_ino, before)
        self.assertEqual((failed / 'payload').read_bytes(), b'failed fresh install')

    def test_rollback_existing_flag_must_match_the_prior_approval(self):
        live, backup = self.rollback_fixture()
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'approval'):
            self.restore_module(backup, False)
        self.assertTrue(live.exists())
        self.assertTrue((backup / 'slsmassnotifyserver').exists())

    def seed_current_stock_cache(self):
        self.prepare()
        self.trust.enroll_sls(self.args.trust_root,*self.previous)
        for module in ('dashboard','framework'):
            data=json.loads((self.workspace/(module+'.json')).read_bytes())
            if module=='dashboard':
                for name in self.upgrade.WIDGETS:data['files'][name]['sha256']=self.trust.digest(self.old['dashboard/'+name])
            body=json.dumps(data).encode();self.trust.store_manifest(self.args.trust_root,data,body)
        self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root)

    def next_framework(self,extra=None):
        contents=dict(self.stock['framework']);contents['module.xml']=b'<module><rawname>framework</rawname><version>17.0.6</version></module>'
        contents.update(extra or {'amp_conf/htdocs/admin/i18n/amp.pot':b'independently signed new translations'})
        plain=self.root/'framework-next.tgz';package(plain,'framework',contents)
        signed=self.offline/'framework-17.0.6.tgz.gpg'
        subprocess.run(self.gpg_command+['--output',str(signed),'--sign',str(plain)],check=True,capture_output=True,timeout=20)
        for name,body in contents.items():
            if not self.upgrade.deployed_framework(name):continue
            target=self.web/(name[16:] if name.startswith('amp_conf/htdocs/') else 'admin/modules/framework/'+name)
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(self.upgrade.menu_overlay(body) if name==self.upgrade.MENU_NAME else body)
        return signed

    def test_stock_reconciliation_accepts_signed_new_version_and_retains_offline_evidence(self):
        self.seed_current_stock_cache();self.next_framework()
        review=self.root/'stock-review'
        result=self.upgrade.reconcile_stock(review,self.args.trust_root,web=self.web,packages=self.offline)
        self.assertEqual(result['changed_modules'],['framework']);self.assertFalse(result['network_allowed'])
        self.assertEqual(self.trust.load(self.args.trust_root,'framework')[0]['version'],'17.0.6')
        self.trust.check(self.args.trust_root,'framework',self.web)
        self.assertTrue((self.args.trust_root/'stock-packages/framework-17.0.6.tgz.gpg').is_file())
        again=self.upgrade.reconcile_stock(self.root/'stock-review-again',self.args.trust_root,web=self.web)
        self.assertEqual(again['changed_modules'],[])
        for name,body in self.preserved.items():self.assertEqual((self.data/name).read_bytes(),body)

    def test_stock_reconciliation_restores_a_pointer_when_enrollment_fails_after_publication(self):
        self.seed_current_stock_cache();self.next_framework()
        pointers={module:(self.args.trust_root/(module+'.active.json')).read_bytes() for module in ('dashboard','framework')}
        original=self.upgrade.TRUST.enroll_reviewed
        def interrupted(root,path,digest):
            original(root,path,digest)
            if Path(path).name=='framework.json':raise OSError('fixture post-publication durability failure')
        with patch.object(self.upgrade.TRUST,'enroll_reviewed',side_effect=interrupted):
            with self.assertRaises(OSError):self.upgrade.reconcile_stock(self.root/'interrupted-stock',self.args.trust_root,web=self.web,packages=self.offline)
        for module,body in pointers.items():self.assertEqual((self.args.trust_root/(module+'.active.json')).read_bytes(),body)
        retry=self.upgrade.reconcile_stock(self.root/'retry-stock',self.args.trust_root,web=self.web)
        self.assertEqual(retry['changed_modules'],['framework'])
        for name,body in self.preserved.items():self.assertEqual((self.data/name).read_bytes(),body)

    def test_stock_cache_refuses_a_dangling_approval_pointer_without_retiring_packages(self):
        self.seed_current_stock_cache()
        folder=self.args.trust_root/'stock-packages';before={p.name:p.read_bytes() for p in folder.iterdir()}
        pointer=self.args.trust_root/'framework.active.json';pointer.unlink();pointer.symlink_to('missing-reference.json')
        with self.assertRaises(Exception):self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root)
        self.assertEqual({p.name:p.read_bytes() for p in folder.iterdir()},before)

    def test_stock_reconciliation_refuses_unknown_bytes_and_missing_offline_package(self):
        self.seed_current_stock_cache();self.next_framework()
        pointers={module:(self.args.trust_root/(module+'.active.json')).read_bytes() for module in ('dashboard','framework')}
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'verified local'):
            self.upgrade.reconcile_stock(self.root/'no-package',self.args.trust_root,web=self.web)
        (self.web/'admin/modules/framework/install.php').write_bytes(b'unreviewed local change')
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'Unreviewed'):
            self.upgrade.reconcile_stock(self.root/'unknown-stock',self.args.trust_root,web=self.web,packages=self.offline)
        for module,body in pointers.items():self.assertEqual((self.args.trust_root/(module+'.active.json')).read_bytes(),body)

    def test_stock_reconciliation_carries_only_reviewed_unchanged_upstream_overlays(self):
        old={'files':{'a':{'sha256':'approved-local','target':'a'}}}
        base={'files':{'a':{'sha256':'signed-base','target':'a'}}}
        current={'files':{'a':{'sha256':'signed-base','target':'a'}}}
        self.upgrade.carry_reviewed_overlays(old,base,current)
        self.assertEqual(current['files']['a'],old['files']['a'])
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'intersects changed upstream'):
            self.upgrade.carry_reviewed_overlays(old,base,{'files':{'a':{'sha256':'changed-signed-base','target':'a'}}})

    def test_reconciliation_lock_keeps_inode_and_accepts_only_verified_inherited_description(self):
        import os
        path=self.root/'maintenance.lock';lock=self.upgrade.coordination_lock(path)
        try:
            inode=path.stat().st_ino
            with self.assertRaisesRegex(self.upgrade.UpgradeError,'maintenance is active'):self.upgrade.coordination_lock(path)
            inherited=self.upgrade.coordination_lock(path,lock);os.close(inherited)
            self.assertEqual(path.stat().st_ino,inode)
            other=self.root/'other.lock';other.write_bytes(b'');other.chmod(0o600)
            descriptor=os.open(other,os.O_RDWR)
            try:
                with self.assertRaisesRegex(self.upgrade.UpgradeError,'lock changed'):self.upgrade.coordination_lock(path,descriptor)
            finally:os.close(descriptor)
        finally:os.close(lock)

    def test_absent_trust_signed_previous_overlays_and_mappings_bootstrap_without_mutation(self):
        self.prepare(); self.assert_preserved()
        approved = json.loads((self.workspace / 'approvals.json').read_bytes())
        self.assertEqual(approved['approved']['dashboard']['files'][self.upgrade.WIDGETS[0]]['sha256'], self.trust.digest(self.new['dashboard/' + self.upgrade.WIDGETS[0]]))
        self.assertEqual(approved['prior']['dashboard']['files'][self.upgrade.WIDGETS[0]]['sha256'], self.trust.digest(self.old['dashboard/' + self.upgrade.WIDGETS[0]]))
        framework = approved['approved']['framework']
        self.assertNotIn('upgrades/15.0/upgrade.php', framework['files'])
        self.assertNotIn('amp_conf/bin/fwconsole', framework['files'])
        self.assertEqual(framework['files'][self.upgrade.MENU_NAME]['target'], 'admin/views/menu_items.php')
        with patch.object(self.upgrade, 'WEB', self.web): self.upgrade.verify_previous(self.workspace)

    def test_same_version_exact_release_alias_preserves_historical_uppercase_approval(self):
        version='0.1.9-beta'
        xml=b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.9-beta</version></module>'
        self.old['module.xml']=xml;self.new['module.xml']=xml
        self.previous=self.release('historical-uppercase',version,self.old,tag='V0.1.9-beta')
        self.candidate=self.release('current-alias',version,self.new,tag='release-0.1.9-beta')
        (self.web/'admin/modules/slsmassnotifyserver/module.xml').write_bytes(xml)
        self.args.archive,self.args.manifest,self.args.signature=self.candidate
        keys=('SLS_MASS_NOTIFY_PREVIOUS_TGZ','SLS_MASS_NOTIFY_PREVIOUS_MANIFEST','SLS_MASS_NOTIFY_PREVIOUS_MANIFEST_SIGNATURE')
        self.environment.update(zip(keys,map(str,self.previous)))
        self.prepare();self.assert_preserved()
        approved=json.loads((self.workspace/'previous-web-approval.json').read_bytes())['slsmassnotifyserver']
        self.assertEqual(approved['version'],version)
        self.assertEqual(approved['source']['archive_sha256'],self.trust.digest(self.previous[0].read_bytes()))
        self.args.workspace=self.root/'wrong-same-version-previous'
        self.environment.update(zip(keys,map(str,self.candidate)))
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'differs from its signed release'):
            self.prepare()
        self.assert_preserved()

    def test_changed_stock_version_rebuilds_signed_inventory_and_rejects_unknown_changes(self):
        self.prepare()
        approvals = json.loads((self.workspace/'approvals.json').read_bytes())
        for name in ('dashboard', 'framework'):
            old = approvals['approved'][name]
            old['version'] = '17.0.4'
            body = json.dumps(old).encode()
            self.trust.store_manifest(self.args.trust_root, self.trust.parse_manifest(body), body)
        self.args.workspace = self.root/'version-review'
        self.prepare()
        current = json.loads((self.args.workspace/'approvals.json').read_bytes())
        self.assertEqual(current['approved']['framework']['version'], '17.0.5')
        self.assertEqual(current['approved']['dashboard']['version'], '17.0.5')
        (self.web/'admin/modules/dashboard/install.php').write_bytes(b'unreviewed customization')
        self.args.workspace = self.root/'unknown-version-review'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed PBX differences'): self.prepare()

    def test_previous_root_mismatch_and_unknown_executable_stop_before_mutation(self):
        target = self.fs / 'usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'
        target.write_bytes(b'unknown runtime')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'differs from its signed'): self.prepare()
        self.assert_preserved()
        target.write_bytes(self.old['bin/sls_mass_notify_update.sh'])
        self.args.workspace = self.root / 'retry-review'
        (target.parent / 'extra.py').write_bytes(b'unknown import')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'unapproved files'): self.prepare()
        self.assert_preserved()
        report = json.loads((self.args.workspace / 'runtime-review-required.json').read_bytes())
        self.assertFalse(report['approved'])
        self.assertEqual(report['differences'][0]['path'], '/usr/local/bin/sls_mass_notify/extra.py')

    def test_missing_signed_helper_restored_before_snapshot_without_changing_existing_files(self):
        target = self.fs / 'usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'
        target.unlink()
        self.prepare(); self.assert_preserved()
        self.assertFalse(target.exists(), 'Trust preparation must remain read-only')
        approved = json.loads((self.workspace / 'previous-root-approval.json').read_bytes())
        self.assertEqual(approved['missing_files'], ['/usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'])
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(target.read_bytes(), self.old['bin/sls_mass_notify_update.sh'])
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assert_preserved()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)

    def test_absent_runtime_rebuilt_only_from_authenticated_previous_sources(self):
        runtime = self.fs / 'usr/local/bin/sls_mass_notify'
        shutil.rmtree(runtime)
        self.prepare(); self.assertFalse(runtime.exists())
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(self.upgrade.runtime_inventory(runtime), {Path(name).name for name in self.upgrade.runtime_files(self.old)})
        self.assert_preserved()

    def prepare_runtime_caches(self, count=1):
        # Extend the signed fixture with an imported helper, as in the real014 runtime.
        self.old['bin/sls_mass_notify/sls_config.py'] = b'VALUE = 1\n'
        self.previous = self.release('previous-python', '0.1.4-beta', self.old)
        for name in ('bin/sls_mass_notify/sls_config.py',):
            path = self.web / 'admin/modules/slsmassnotifyserver' / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(self.old[name])
        runtime = self.fs / 'usr/local/bin/sls_mass_notify'
        (runtime / 'sls_config.py').write_bytes(self.old['bin/sls_mass_notify/sls_config.py'])
        self.environment['SLS_MASS_NOTIFY_PREVIOUS_TGZ'], self.environment['SLS_MASS_NOTIFY_PREVIOUS_MANIFEST'], self.environment['SLS_MASS_NOTIFY_PREVIOUS_MANIFEST_SIGNATURE'] = map(str, self.previous)
        directory = runtime / '__pycache__'
        directory.mkdir()
        caches = [directory / ('sls_config.cpython-311' + ('.opt-1' if index else '') + '.pyc') for index in range(count)]
        for cache in caches:
            cache.write_bytes(b'untrusted bytecode must not execute or be restored')
        self.prepare(); self.assert_preserved()
        return caches

    def test_cache_quarantine_keeps_bytecode_out_of_execution_approval_and_rollback(self):
        cache, = self.prepare_runtime_caches()
        approved = json.loads((self.workspace / 'previous-root-approval.json').read_bytes())
        self.assertNotIn('/usr/local/bin/sls_mass_notify/__pycache__/sls_config.cpython-311.pyc', approved['files'])
        self.assertEqual(len(approved['quarantine_caches']), 1)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse(cache.exists())
        evidence = json.loads((self.workspace / 'runtime-cache-recovery/inventory.json').read_bytes())
        self.assertFalse(evidence['execution_approved'])
        digest = self.trust.digest(('/usr/local/bin/sls_mass_notify/__pycache__/' + cache.name).encode())
        saved = self.workspace / 'runtime-cache-recovery' / digest
        self.assertEqual(saved.read_bytes(), b'untrusted bytecode must not execute or be restored')
        evidence_before = {path.name: (path.read_bytes(), path.stat().st_ino) for path in saved.parent.iterdir()}
        with patch.object(self.upgrade, 'WEB', self.web):
            self.upgrade.verify_previous(self.workspace)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse(cache.exists())
        self.assertEqual(evidence_before, {path.name: (path.read_bytes(), path.stat().st_ino) for path in saved.parent.iterdir()})
        self.assert_preserved()

    def test_partial_cache_quarantine_resumes_without_replacing_signed_helpers(self):
        first, second = self.prepare_runtime_caches(count=2)
        helper = first.parent.parent / 'sls_mass_notify_update.sh'
        helper_before = (helper.read_bytes(), helper.stat().st_ino)
        unlink = self.upgrade.os.unlink
        removed = []

        def interrupt_second(path, *args, **kwargs):
            if path in {first.name, second.name} and 'dir_fd' in kwargs:
                if removed:
                    raise OSError('fixture: interrupted after first quarantine')
                result = unlink(path, *args, **kwargs)
                removed.append(path)
                return result
            return unlink(path, *args, **kwargs)

        with patch.object(self.upgrade.os, 'unlink', side_effect=interrupt_second):
            with self.assertRaisesRegex(OSError, 'interrupted after first'):
                self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(sum(cache.exists() for cache in (first, second)), 1)
        self.assert_preserved()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse(first.exists()); self.assertFalse(second.exists())
        self.assertEqual(helper_before, (helper.read_bytes(), helper.stat().st_ino))
        self.assert_preserved()

    def test_cache_disappearance_without_quarantine_cannot_authorize_helper_repair(self):
        helper = self.fs / 'usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'
        helper.unlink()
        cache, = self.prepare_runtime_caches()
        cache.unlink()
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'absent without valid private quarantine evidence'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse((self.workspace / 'runtime-cache-recovery').exists())
        self.assertFalse(helper.exists())
        self.assert_preserved()

    def test_repeated_cache_check_rejects_missing_or_changed_quarantine_inventory(self):
        self.prepare_runtime_caches()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        inventory = self.workspace / 'runtime-cache-recovery/inventory.json'
        original = inventory.read_bytes()
        approved = json.loads(original)
        invalid = [None, b'{', b'[]', json.dumps({**approved, 'schema': True}).encode(),
                   json.dumps({**approved, 'execution_approved': True}).encode(),
                   json.dumps({**approved, 'execution_approved': 0}).encode(),
                   json.dumps({**approved, 'files': {}}).encode()]
        for body in invalid:
            with self.subTest(body=body):
                if body is None:
                    inventory.unlink()
                else:
                    inventory.write_bytes(body)
                with self.assertRaises(self.upgrade.UpgradeError):
                    self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
                if body is not None:
                    self.assertEqual(inventory.read_bytes(), body)
                self.assert_preserved()
                inventory.write_bytes(original)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)

    def test_repeated_cache_check_rejects_unsafe_or_missing_quarantine_bytes(self):
        cache, = self.prepare_runtime_caches()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        absolute = self.upgrade.RUNTIME + '/__pycache__/' + cache.name
        saved = self.workspace / 'runtime-cache-recovery' / self.trust.digest(absolute.encode())
        original = saved.read_bytes()
        for alteration in ('changed', 'missing', 'symlink', 'hardlink', 'writable', 'oversized'):
            with self.subTest(alteration=alteration):
                saved.unlink()
                extra = self.root / 'quarantine-fixture'
                if alteration == 'changed':
                    saved.write_bytes(b'changed cache evidence')
                elif alteration == 'symlink':
                    extra.write_bytes(original); saved.symlink_to(extra)
                elif alteration == 'hardlink':
                    extra.write_bytes(original); os.link(extra, saved)
                elif alteration == 'writable':
                    saved.write_bytes(original); saved.chmod(0o666)
                elif alteration == 'oversized':
                    saved.write_bytes(b'x' * (1024 * 1024 + 1))
                with self.assertRaises(self.upgrade.UpgradeError):
                    self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
                self.assertFalse(cache.exists()); self.assert_preserved()
                if saved.exists() or saved.is_symlink():
                    saved.unlink()
                if extra.exists():
                    self.assertEqual(extra.read_bytes(), original); extra.unlink()
                saved.write_bytes(original); saved.chmod(0o600)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)

    def test_repeated_cache_check_requires_private_recovery_directory(self):
        self.prepare_runtime_caches()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        evidence = self.workspace / 'runtime-cache-recovery'
        evidence.chmod(0o755)
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'private quarantine evidence'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        evidence.chmod(0o700)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assert_preserved()

    def test_runtime_changes_after_cache_quarantine_still_require_review(self):
        cache, = self.prepare_runtime_caches()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        source = cache.parent.parent / 'sls_config.py'
        original = source.read_bytes()
        source.write_bytes(b'changed executable source')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Previous runtime changed after preflight'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(source.read_bytes(), b'changed executable source')
        source.write_bytes(original)
        unknown = source.parent / 'unknown.py'; unknown.write_bytes(b'new unknown executable')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'no additional files were approved'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(unknown.read_bytes(), b'new unknown executable'); unknown.unlink()
        cache.write_bytes(b'changed recreated bytecode')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Python cache changed after preflight'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(cache.read_bytes(), b'changed recreated bytecode')
        self.assert_preserved()

    def test_new_approval_after_completed_quarantine_supports_upgrade_retry(self):
        self.prepare_runtime_caches()
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.args.workspace = self.workspace = self.root / 'retry-review'
        self.prepare()
        approval = json.loads((self.workspace / 'previous-root-approval.json').read_bytes())
        self.assertEqual(approval['quarantine_caches'], {})
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assert_preserved()

    def test_unknown_cache_content_links_and_writable_entries_remain_blocked(self):
        runtime = self.fs / 'usr/local/bin/sls_mass_notify'
        cache = runtime / '__pycache__/injected.py'
        cache.parent.mkdir(); cache.write_bytes(b'unknown code')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'unapproved files'): self.prepare()
        self.assert_preserved(); cache.unlink()
        cache.symlink_to(runtime / 'sls_mass_notify_update.sh')
        self.args.workspace = self.root / 'link-review'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unsafe link'): self.prepare()
        self.assert_preserved(); cache.unlink()
        cache.write_bytes(b'unknown code'); cache.chmod(0o666)
        self.args.workspace = self.root / 'writable-review'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unprotected previous'): self.prepare()
        self.assert_preserved()

    def test_repair_never_overwrites_a_changed_file_or_trusts_tampered_payload(self):
        target = self.fs / 'usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'
        target.unlink(); self.prepare()
        repair = self.workspace / 'previous-runtime-repairs' / self.trust.digest('/usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'.encode())
        original = repair.read_bytes(); repair.write_bytes(b'changed private repair payload')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'changed after preflight'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse(target.exists()); repair.write_bytes(original)
        target.write_bytes(b'new unapproved destination')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'changed after preflight'):
            self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(target.read_bytes(), b'new unapproved destination'); self.assert_preserved()

    def test_runtime_normalization_precedes_snapshot_and_inventory_only_remains_read_only(self):
        installer = (ROOT / 'tools/install_release.sh').read_text()
        preparation = installer.split('prepare_authenticated_installer() {', 1)[1].split('\n# The protected log opener', 1)[0]
        self.assertLess(preparation.index('SLS_MASS_NOTIFY_INVENTORY_ONLY'), preparation.index('--normalize-runtime'))
        self.assertLess(preparation.index('--normalize-runtime'), preparation.index('prepare_install_recovery ||'))

    def test_fresh_normalization_leaves_unrelated_runtime_untouched(self):
        self.workspace.mkdir(mode=0o700)
        self.upgrade.write_json(self.workspace / 'previous-root-approval.json',
                                {'schema': 1, 'source': 'fresh-install', 'files': {}, 'root_jobs': []})
        self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertEqual(self.upgrade.runtime_inventory(self.fs / 'usr/local/bin/sls_mass_notify'),
                         {Path(name).name for name in self.upgrade.runtime_files(self.old)})

    def test_failed_repair_write_does_not_publish_a_partial_runtime_helper(self):
        target = self.fs / 'usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'
        target.unlink(); self.prepare()
        with patch.object(self.upgrade.os, 'fsync', side_effect=OSError('fixture: no space left on device')):
            with self.assertRaises(OSError):
                self.upgrade.normalize_previous_runtime(self.workspace, prefix=self.fs)
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.glob('.previous-runtime-*')), [])
        self.assert_preserved()

    def test_unknown_stock_changes_produce_review_report_without_becoming_approved(self):
        target = self.web / 'admin/modules/dashboard/install.php'; target.write_bytes(b'local reviewed work required')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed PBX differences'): self.prepare()
        self.assertEqual(target.read_bytes(), b'local reviewed work required'); self.assert_preserved()
        report = json.loads((self.workspace / 'review-required.json').read_bytes())
        self.assertFalse(report['approved']); self.assertIn('install.php', [row['path'] for row in report['differences']])
        self.assertFalse((self.workspace / 'dashboard.json').exists())

    def test_spinner_alias_requires_same_signed_target_bytes(self):
        spinner = self.web / 'admin/images/spinner.gif'; spinner.unlink()
        target = self.web / 'admin/modules/core/images/spinner.gif'; target.parent.mkdir(parents=True); target.write_bytes(self.stock['framework'][self.upgrade.SPINNER])
        spinner.symlink_to(target)
        self.prepare()
        inventory = json.loads((self.workspace / 'framework.json').read_bytes())
        self.assertEqual(inventory['files'][self.upgrade.SPINNER]['link_target'], 'admin/modules/core/images/spinner.gif')
        target.write_bytes(b'changed GIF')
        self.args.workspace = self.root / 'changed-review'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed PBX differences'): self.prepare()

    def test_tampered_previous_release_rejected_and_retry_accepts_signed_original(self):
        original = self.previous[2].read_bytes(); self.previous[2].write_bytes(b'0' * 64)
        with self.assertRaises(self.trust.TrustError): self.prepare()
        self.assert_preserved(); self.previous[2].write_bytes(original)
        self.args.workspace = self.root / 'retry-review'; self.prepare(); self.assert_preserved()

    def test_unverified_upstream_and_wrong_version_are_rejected(self):
        path = self.offline / 'dashboard-17.0.5.tgz.gpg'
        body = path.read_bytes(); path.write_bytes(body[:-32] + b'0' * 32)
        with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
        self.assert_preserved(); path.write_bytes(body)
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'does not match'):
            self.upgrade.upstream_contents(path, 'dashboard', '17.0.99', self.root)

    def test_revoked_or_unapproved_prior_jobs_never_gain_restore_approval(self):
        self.cron += b'* * * * * /usr/local/bin/sls_mass_notify/arbitrary.php\n'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'needs independent review'): self.prepare()
        self.assert_preserved()

    def test_local_overlay_preserved_when_explicit_independent_inventory_matches(self):
        self.prepare()
        local = self.web / 'admin/modules/framework/local-branding.php'; local.write_bytes(b'reviewed fixture branding')
        inventory = json.loads((self.workspace / 'framework.json').read_bytes())
        inventory['files']['local-branding.php'] = {'sha256': self.trust.digest(b'reviewed fixture branding'), 'target': 'admin/modules/framework/local-branding.php'}
        path = self.root / 'reviewed-framework.json'; digest = self.upgrade.write_json(path, inventory)
        self.environment.update(SLS_MASS_NOTIFY_FRAMEWORK_INVENTORY=str(path), SLS_MASS_NOTIFY_FRAMEWORK_INVENTORY_SHA256=digest)
        self.args.workspace = self.root / 'reviewed-retry'; self.prepare()
        self.assertEqual(local.read_bytes(), b'reviewed fixture branding'); self.assert_preserved()
        local.write_bytes(b'unknown later edit')
        with patch.object(self.upgrade, 'WEB', self.web), self.assertRaises(self.trust.TrustError): self.upgrade.verify_previous(self.args.workspace)

    def test_mismatched_installed_previous_module_is_not_auto_approved(self):
        target = self.web / 'admin/modules/slsmassnotifyserver/bin/sls_mass_notify_update.sh'; target.write_bytes(b'unknown live code')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Installed previous SLL file differs'): self.prepare()
        self.assert_preserved()

    def test_absent_dashboard_bootstraps_only_independently_signed_stock(self):
        shutil.rmtree(self.web/'admin/modules/dashboard')
        with patch.object(self.upgrade,'WEB',self.web),patch.dict(os.environ,self.environment,clear=True):
            self.upgrade.bootstrap_dashboard(self.root/'stock-bootstrap','17.0.5')
        for name,body in self.stock['dashboard'].items():
            self.assertEqual((self.web/'admin/modules/dashboard'/name).read_bytes(),body)
        self.assertFalse(self.args.trust_root.exists())
        self.assert_preserved()

    def test_existing_dashboard_is_never_replaced_by_stock_bootstrap(self):
        path=self.web/'admin/modules/dashboard/module.xml';before=path.read_bytes()
        with patch.object(self.upgrade,'WEB',self.web),self.assertRaisesRegex(self.upgrade.UpgradeError,'absent'):
            self.upgrade.bootstrap_dashboard(self.root/'stock-bootstrap','17.0.5')
        self.assertEqual(path.read_bytes(),before)

    def test_dashboard_metadata_failure_never_publishes_an_unreadable_module(self):
        shutil.rmtree(self.web/'admin/modules/dashboard')
        actual_chmod = self.upgrade.os.fchmod
        def fail_metadata(descriptor, mode):
            path = os.readlink('/proc/self/fd/' + str(descriptor))
            if path.startswith(str(self.web/'admin/modules') + '/') and path.endswith('/module.xml') and mode == 0o644:
                raise OSError('injected stock metadata failure')
            return actual_chmod(descriptor, mode)
        with patch.object(self.upgrade, 'WEB', self.web), patch.dict(os.environ, self.environment, clear=True), \
                patch.object(self.upgrade.os, 'fchmod', side_effect=fail_metadata), \
                self.assertRaisesRegex(OSError, 'stock metadata failure'):
            self.upgrade.bootstrap_dashboard(self.root/'stock-bootstrap', '17.0.5')
        self.assertFalse((self.web/'admin/modules/dashboard').exists(),
                         'A failed metadata preparation exposed a half-installed Dashboard to native FreePBX.')
        retained = list((self.web/'admin/modules').glob('.sls-stock-dashboard-*'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].stat().st_mode & 0o777, 0o700)
        self.assertTrue((self.root/'stock-bootstrap/stock-bootstrap.json').is_file())
        self.assert_preserved()

    def test_dashboard_appearing_before_publication_is_preserved(self):
        destination = self.web/'admin/modules/dashboard'
        shutil.rmtree(destination)
        actual_chmod = self.upgrade.os.fchmod
        def add_existing_dashboard(descriptor, mode):
            path = os.readlink('/proc/self/fd/' + str(descriptor))
            if path.endswith('/tree') and mode == 0o755 and not destination.exists():
                destination.mkdir()
                (destination/'operator-file').write_bytes(b'existing local module')
            return actual_chmod(descriptor, mode)
        with patch.object(self.upgrade, 'WEB', self.web), patch.dict(os.environ, self.environment, clear=True), \
                patch.object(self.upgrade.os, 'fchmod', side_effect=add_existing_dashboard), \
                self.assertRaisesRegex(self.upgrade.UpgradeError, 'appeared'):
            self.upgrade.bootstrap_dashboard(self.root/'stock-bootstrap', '17.0.5')
        self.assertEqual((destination/'operator-file').read_bytes(), b'existing local module')
        self.assertFalse((destination/'module.xml').exists())
        retained = list((self.web/'admin/modules').glob('.sls-stock-dashboard-*'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].stat().st_mode & 0o777, 0o700)
        self.assertTrue((retained[0]/'tree/module.xml').is_file())


if __name__ == '__main__': unittest.main()
