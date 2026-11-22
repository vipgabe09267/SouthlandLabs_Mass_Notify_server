#!/usr/bin/python3
"""Signed old-to-new upgrade fixtures; no live PBX paths, network or services."""
import argparse
import copy
import errno
import importlib.util
import io
import json
import os
import pwd
from pathlib import Path
import shutil
import stat
import struct
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

    def test_signed_stock_private_workspace_keeps_gpg_isolation_and_signature_checks(self):
        private='/var/spool/sls-mass-notify-installer-tmp'
        real_temporary=self.upgrade.tempfile.TemporaryDirectory
        homes=[]
        def isolated(*args,**kwargs):
            self.assertEqual(Path(kwargs['dir']),Path(private))
            kwargs['dir']='/tmp'
            result=real_temporary(*args,**kwargs)
            self.assertEqual(Path(result.name).stat().st_mode&0o777,0o700)
            homes.append(result.name)
            return result
        with patch.dict(os.environ,{'TMPDIR':private}), patch.object(self.upgrade,'private_install_temporary_state',return_value={'exists':True},create=True) as checked, patch.object(self.upgrade.tempfile,'TemporaryDirectory',side_effect=isolated):
            result,proof=self.upgrade.upstream_contents(self.offline/'framework-17.0.5.tgz.gpg','framework','17.0.5',self.root)
        self.assertEqual(result,self.stock['framework']);self.assertEqual(proof['upstream_signer'],self.upgrade.UPSTREAM_SIGNER);checked.assert_called_once_with()
        self.assertTrue(homes);self.assertTrue(all(not Path(p).exists()for p in homes))
        longest=private+'/sls-upstream-gpg-'+'x'*8+'/S.gpg-agent.browser'
        self.assertLess(len(longest.encode()),108)
        with patch.dict(os.environ,{'TMPDIR':private}), patch.object(self.upgrade,'private_install_temporary_state',side_effect=ValueError('unsafe'),create=True), patch.object(self.upgrade.subprocess,'run') as started:
            with self.assertRaises(self.upgrade.UpgradeError):self.upgrade.upstream_contents(self.offline/'framework-17.0.5.tgz.gpg','framework','17.0.5',self.root)
            started.assert_not_called()

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

    def test_complete_stock_cache_capacity_binding_covers_native_versions_and_existing_pending(self):
        self.seed_current_stock_cache()
        binding_api=getattr(self.upgrade,'stock_cache_storage_binding',None)
        self.assertTrue(callable(binding_api),'Authenticated complete stock cache growth proof is missing')
        folder=self.args.trust_root/'stock-packages';before={p.name:p.read_bytes()for p in folder.iterdir()}
        binding=binding_api(self.workspace,self.args.trust_root,web=self.web)
        self.assertIsInstance(binding,dict)
        self.assertEqual(set(binding['approved']),{'dashboard','framework'})
        self.assertEqual(set(binding['cached']),{'dashboard-17.0.5.tgz.gpg','framework-17.0.5.tgz.gpg'})
        self.assertEqual(binding['pending'],binding['cached'])
        self.assertEqual({p.name:p.read_bytes()for p in folder.iterdir()},before)

    def test_discounted_stock_publication_stops_before_writes_if_bound_cache_drifted(self):
        self.seed_current_stock_cache();api=getattr(self.upgrade,'stock_cache_storage_binding',None)
        self.assertTrue(callable(api),'Protected cache checkpoint binding is missing')
        binding=api(self.workspace,self.args.trust_root,web=self.web)
        proof={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':binding}
        path=self.workspace/'resource-relationship-proof.json';self.upgrade.write_json(path,proof)
        digest=self.trust.digest(json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
        target=self.args.trust_root/'stock-packages/framework-17.0.5.tgz.gpg';target.write_bytes(b'changed root cache')
        before={p.name:p.read_bytes()for p in target.parent.iterdir()}
        with patch.object(self.upgrade,'WEB',self.web),patch.object(self.upgrade,'upstream_contents',side_effect=AssertionError('No GPG/temp or publication after drift')),self.assertRaisesRegex(self.upgrade.UpgradeError,'capacity|storage|changed'):
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root,capacity_proof=path,capacity_proof_sha256=digest)
        self.assertEqual({p.name:p.read_bytes()for p in target.parent.iterdir()},before)

    def test_discounted_stock_writer_rechecks_current_native_version_before_any_publication(self):
        self.seed_current_stock_cache()
        binding=self.upgrade.stock_cache_storage_binding(self.workspace,self.args.trust_root,web=self.web)
        self.assertIsInstance(binding,dict)
        proof={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':binding}
        path=self.workspace/'resource-relationship-proof.json';self.upgrade.write_json(path,proof)
        digest=self.trust.digest(json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
        xml=self.web/'admin/modules/framework/module.xml';xml.write_bytes(b'<module><rawname>framework</rawname><version>17.0.99</version></module>')
        before={p.name:p.read_bytes()for p in(self.args.trust_root/'stock-packages').iterdir()}
        with patch.object(self.upgrade,'WEB',self.web),patch.object(self.upgrade,'upstream_contents',side_effect=AssertionError('No GPG/write after native drift')),self.assertRaises(self.upgrade.UpgradeError):
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root,capacity_proof=path,capacity_proof_sha256=digest)
        self.assertEqual({p.name:p.read_bytes()for p in(self.args.trust_root/'stock-packages').iterdir()},before)

    def test_stock_role_is_rechecked_after_gpg_before_any_cache_publication(self):
        self.seed_current_stock_cache()
        binding=self.upgrade.stock_cache_storage_binding(self.workspace,self.args.trust_root,web=self.web)
        proof={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':binding}
        path=self.workspace/'resource-relationship-proof.json';self.upgrade.write_json(path,proof)
        digest=self.trust.digest(json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
        folder=self.args.trust_root/'stock-packages';before={p.name:p.read_bytes()for p in folder.iterdir()}
        cache_identity=(folder.stat().st_dev,folder.stat().st_ino)
        original=self.upgrade.upstream_contents;original_unlink=self.upgrade.os.unlink;calls=[]
        def verified_then_drift(*args,**kwargs):
            result=original(*args,**kwargs);calls.append(1)
            if len(calls)==1:
                (self.web/'admin/modules/framework/module.xml').write_bytes(b'<module><rawname>framework</rawname><version>17.0.99</version></module>')
            return result
        def no_cache_retirement(name,*args,**kwargs):
            fd=kwargs.get('dir_fd')
            if fd is not None:
                row=os.fstat(fd)
                if(row.st_dev,row.st_ino)==cache_identity:raise AssertionError('No cache retirement after proof drift')
            return original_unlink(name,*args,**kwargs)
        with patch.object(self.upgrade,'WEB',self.web),patch.object(self.upgrade,'upstream_contents',side_effect=verified_then_drift), \
             patch.object(self.trust,'atomic',side_effect=AssertionError('No publication after proof drift')), \
             patch.object(self.upgrade.os,'unlink',side_effect=no_cache_retirement),self.assertRaises(self.upgrade.UpgradeError):
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root,capacity_proof=path,capacity_proof_sha256=digest)
        self.assertGreaterEqual(len(calls),1,'First capacity proof must pass and actual GPG validation must run before the controlled drift')
        self.assertEqual({p.name:p.read_bytes()for p in folder.iterdir()},before)

    def test_malformed_native_identity_declines_credit_and_writer_fails_with_bounded_error(self):
        self.seed_current_stock_cache()
        binding=self.upgrade.stock_cache_storage_binding(self.workspace,self.args.trust_root,web=self.web)
        self.assertIsInstance(binding,dict)
        proof={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':binding}
        path=self.workspace/'resource-relationship-proof.json';self.upgrade.write_json(path,proof)
        digest=self.trust.digest(json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
        (self.web/'admin/modules/framework/module.xml').write_bytes(b'<module>PRIVATE_XML_SENTINEL')
        self.assertIsNone(self.upgrade.stock_cache_storage_binding(self.workspace,self.args.trust_root,web=self.web))
        with patch.object(self.upgrade,'WEB',self.web),patch.object(self.trust,'atomic',side_effect=AssertionError('No publication')),self.assertRaises(self.upgrade.UpgradeError)as caught:
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root,capacity_proof=path,capacity_proof_sha256=digest)
        self.assertNotIn('PRIVATE_XML_SENTINEL',str(caught.exception))

    def test_missing_interrupted_foreign_or_new_pending_cache_keeps_full_reservation(self):
        self.seed_current_stock_cache();api=getattr(self.upgrade,'stock_cache_storage_binding',None)
        self.assertTrue(callable(api),'Conservative stock cache proof is missing')
        folder=self.args.trust_root/'stock-packages'
        for change in('missing','interrupted','new_pending','foreign'):
            with self.subTest(change=change):
                leaf=folder/'framework-17.0.5.tgz.gpg';original=leaf.read_bytes();extra=None
                if change=='missing':leaf.unlink()
                elif change=='interrupted':extra=folder/('.new-'+'a'*24);extra.write_bytes(original);extra.chmod(0o600)
                elif change=='foreign':extra=folder/'unknown';extra.write_bytes(original);extra.chmod(0o600)
                else:extra=self.workspace/'framework-17.0.99.tgz.gpg';extra.write_bytes(original);extra.chmod(0o600)
                self.assertIsNone(api(self.workspace,self.args.trust_root,web=self.web))
                if extra is not None:extra.unlink()
                if change=='missing':leaf.write_bytes(original);leaf.chmod(0o600)

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
            target.write_bytes(body)
        return signed

    def test_interrupted_stock_evidence_preserves_cache_when_trust_volume_is_full(self):
        self.seed_current_stock_cache()
        folder=self.args.trust_root/'stock-packages'
        package=folder/'framework-17.0.5.tgz.gpg'
        partial=folder/('.new-'+'8'*24)
        self.trust.atomic(partial,package.read_bytes())
        before={p.name:p.read_bytes() for p in folder.iterdir()}
        root_identity=self.args.trust_root.stat()
        real_statvfs=os.fstatvfs
        def capacity(fd):
            actual=os.fstat(fd)
            if (actual.st_dev,actual.st_ino)==(root_identity.st_dev,root_identity.st_ino):
                from types import SimpleNamespace
                return SimpleNamespace(f_bavail=0,f_frsize=4096,f_files=100,f_favail=100,f_flag=0)
            return real_statvfs(fd)
        with patch.object(os,'fstatvfs',side_effect=capacity), self.assertRaisesRegex(self.upgrade.UpgradeError,'capacity|space'):
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root)
        self.assertEqual({p.name:p.read_bytes() for p in folder.iterdir()},before)
        self.assertEqual(list(self.args.trust_root.glob('.stock-cache-recovery-*')),[])

    def test_new_native_signed_stock_package_publishes_after_exact_growth_check(self):
        self.seed_current_stock_cache()
        signed = self.next_framework()
        name = signed.name
        body = signed.read_bytes()
        self.trust.atomic(self.workspace/name,body)
        contents, provenance = self.upgrade.upstream_contents(signed,'framework','17.0.6',self.workspace)
        current,unused = self.upgrade.upstream_inventory(contents,provenance,'framework','17.0.6',self.old,self.old,self.web)
        self.upgrade.write_json(self.workspace/'framework.json',current)
        # Dashboard's staged package was already present. The previous
        # Framework package remains cached even after the new one is published.
        binding=self.upgrade.stock_cache_storage_binding(self.workspace,self.args.trust_root,web=self.web)
        self.assertIsInstance(binding,dict)
        self.assertEqual(set(binding['pending'])-set(binding['cached']),{name})
        self.assertEqual(binding['pending'][name]['bytes'],len(body))
        proof={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':binding}
        path=self.workspace/'resource-relationship-proof.json'
        self.upgrade.write_json(path,proof)
        digest=self.trust.digest(json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
        folder=self.args.trust_root/'stock-packages'
        old=(folder/'framework-17.0.5.tgz.gpg').read_bytes()
        with patch.object(self.upgrade,'WEB',self.web):
            self.upgrade.cache_stock_packages(self.workspace,self.args.trust_root,capacity_proof=path,capacity_proof_sha256=digest)
        self.assertEqual((folder/name).read_bytes(),body)
        self.assertEqual((folder/'framework-17.0.5.tgz.gpg').read_bytes(),old)

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

    def stock_step(self, root, action, **options):
        # The shell fixture's guarded signers produce an exact digest for each
        # successfully verified module. Some old synthetic packages omit .sig.
        if action == 'complete' and 'verified_signatures' not in options:
            outputs = {}
            for module in ('dashboard','framework'):
                path = self.web/'admin/modules'/module/'module.sig'
                if not path.exists(): path.write_bytes(('verified fixture signature '+module).encode())
                outputs[module] = self.trust.digest(path.read_bytes())
            options['verified_signatures'] = outputs
        return self.upgrade.stock_maintenance(root, action, **options)

    def test_completion_binds_verified_menu_and_both_actual_signer_outputs(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        menu = self.web/'admin/views/menu_items.php'
        menu.write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        signatures = {m:self.web/'admin/modules'/m/'module.sig' for m in ('dashboard','framework')}
        def step(action, **kw):
            return self.upgrade.stock_maintenance(root, action, web=self.web, packages=self.offline,
                                                  now=1700000000, **kw)
        for change in ('menu','dashboard','framework','missing proof','legitimate published signatures','edit during publication'):
            with self.subTest(change=change):
                menu.write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
                for m,p in signatures.items(): p.write_bytes(('old '+m).encode())
                step('reserve'); step('reconcile')
                for m,p in signatures.items(): p.write_bytes(('verified '+m).encode())
                proofs = {m:self.trust.digest(p.read_bytes()) for m,p in signatures.items()}
                if change == 'menu': menu.write_bytes(b'concurrent unexpected menu')
                elif change in signatures: signatures[change].write_bytes(b'concurrent unexpected signature')
                elif change == 'missing proof': del proofs['dashboard']
                if change in ('legitimate published signatures','edit during publication'):
                    save = self.upgrade.write_json
                    def concurrent_publication(path, payload):
                        if change == 'edit during publication' and path.name == 'stock-maintenance.json' and payload['phase'] == 'complete':
                            signatures['dashboard'].write_bytes(b'changed after the last comparison')
                        return save(path,payload)
                    with patch.object(self.upgrade,'write_json',side_effect=concurrent_publication):
                        self.assertEqual(step('complete',verified_signatures=proofs),'complete')
                    if change == 'legitimate published signatures':
                        self.assertEqual(step('probe'),'current')
                    else:
                        self.assertNotEqual(step('probe'),'current')
                else:
                    with self.assertRaisesRegex(self.upgrade.UpgradeError,'verified|Verified'):
                        step('complete',verified_signatures=proofs)
                    self.assertNotEqual(json.loads((root/'stock-maintenance.json').read_bytes())['phase'],'complete')
                    if change in signatures or change == 'menu':
                        self.assertTrue((root/'stock-maintenance-review.json').exists())
                    step('failed')

    def test_maintenance_discovers_stock_updates_even_with_intact_widgets_and_rechecks_replaced_signature(self):
        self.seed_current_stock_cache()
        (self.web/'admin/views/menu_items.php').write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        root = self.args.trust_root
        def step(action, now=1700000000):
            return self.stock_step(root, action, web=self.web, packages=self.offline, now=now)
        self.assertEqual(step('probe'), 'due')
        step('reserve')
        step('reconcile')
        step('complete')
        self.assertEqual(step('probe'), 'current')
        self.next_framework()
        self.assertEqual(step('probe'), 'due')
        step('reserve')
        step('reconcile')
        self.assertEqual(self.trust.load(root, 'framework')[0]['version'], '17.0.6')
        step('complete')
        self.assertEqual(step('probe'), 'current')
        (self.web/'admin/modules/framework/module.sig').write_bytes(b'replaced signature')
        self.assertEqual(step('probe',1700000300), 'due')

    def test_stock_update_during_signing_retries_version_never_attempted(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        (self.web/'admin/views/menu_items.php').write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        def step(action, minute):
            return self.stock_step(root, action, web=self.web, packages=self.offline,
                                                  now=1700000000 + 60*minute)
        step('reserve',0)
        step('reconcile',0)
        self.next_framework()
        self.assertEqual(step('failed',1),'transition')
        state = json.loads((root/'stock-maintenance.json').read_bytes())
        self.assertEqual(state['attempted']['versions']['framework'],'17.0.5')
        self.assertEqual(state['seen']['versions']['framework'],'17.0.6')
        self.assertEqual(self.trust.load(root,'framework')[0]['version'],'17.0.5')
        self.assertEqual(step('probe',5),'waiting')
        self.assertEqual(step('probe',6),'due')
        for action in ('reserve','reconcile','complete'): step(action,6)
        self.assertEqual(step('probe',7),'current')
        self.assertEqual(self.trust.load(root,'framework')[0]['version'],'17.0.6')

    def test_stock_update_with_new_xml_but_old_payload_retries_after_updater_finishes(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        module = self.web/'admin/modules/framework'
        previous = (module/'install.php').read_bytes()
        self.next_framework({'install.php':b'signed new installer','module.sig':b'new native signature'})
        (module/'install.php').write_bytes(previous)
        (module/'module.sig').write_bytes(b'previous native signature')
        def step(action, minute):
            return self.stock_step(root, action, web=self.web, packages=self.offline,
                                                  now=1700000000 + 60*minute)
        step('reserve',0)
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'review'): step('reconcile',0)
        self.assertEqual(step('failed',0),'transition')
        self.assertEqual(self.trust.load(root,'framework')[0]['version'],'17.0.5')
        self.assertIn('install.php',{i['path'] for i in json.loads((root/'stock-maintenance-review.json').read_bytes())['differences']})
        self.assertEqual(step('probe',1),'waiting')
        self.assertEqual(step('probe',5),'due')
        step('reserve',5)
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'review'): step('reconcile',5)
        self.assertEqual(step('failed',5),'transition')
        (module/'install.php').write_bytes(b'signed new installer')
        (module/'module.sig').write_bytes(b'new native signature')
        self.assertEqual(step('probe',6),'waiting')
        self.assertEqual(step('probe',20),'due')
        for action in ('reserve','reconcile','complete'): step(action,20)
        self.assertEqual(step('probe',21),'current')
        self.assertEqual(self.trust.load(root,'framework')[0]['version'],'17.0.6')

    def test_old_pending_stock_receipt_retries_once_and_interrupted_review_backs_off(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        record = root/'stock-maintenance.json'
        start = 1700000000
        self.upgrade.write_json(record, {'schema':1,'phase':'pending','time':start,
                                        'seen':self.upgrade.stock_observation(root,self.web)})
        def step(action, minute):
            return self.stock_step(root, action, web=self.web, packages=self.offline,
                                                  now=start + 60*minute)
        self.assertEqual(step('probe',1),'due')
        step('reserve',1)
        self.assertEqual(step('probe',2),'waiting')
        self.assertEqual(step('probe',6),'due')
        step('reserve',6)
        self.assertEqual(step('probe',11),'waiting')
        self.assertEqual(step('probe',21),'due')

    def test_stock_cron_ignores_metadata_only_rewrites_and_bounds_genuinely_changing_signatures(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        module = self.web/'admin/modules/framework'
        menu = self.web/'admin/views/menu_items.php'
        menu.write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        signature = module/'module.sig'
        signature.write_bytes(b'fixture signature')
        def step(action, minute):
            return self.stock_step(root, action, web=self.web, packages=self.offline,
                                                  now=1700000000 + minute * 60)
        step('reserve',0)
        step('reconcile',0)
        step('complete',0)
        before = signature.read_bytes()
        temp = signature.with_name('replacement')
        temp.write_bytes(before)
        temp.replace(signature)
        os.utime(menu, None)
        self.assertEqual(step('probe',1),'current')
        step('reserve',5)
        step('failed',5)
        for minute in range(6,65):
            signature.write_text('changed invalid signature at minute ' + str(minute))
            self.assertEqual(step('probe',minute),'waiting')
        self.assertEqual(step('probe',65),'due')
        step('reserve',65)
        step('failed',65)
        self.next_framework()
        self.assertEqual(step('probe',70),'due')

    def test_stock_probe_skips_oversized_and_special_inputs_without_reading_their_bodies(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        signature = self.web/'admin/modules/framework/module.sig'
        with signature.open('wb') as stream:
            stream.truncate(256 * 1024 * 1024)
        menu = self.web/'admin/views/menu_items.php'
        menu.unlink(); os.mkfifo(menu)
        original = self.trust.read
        def bounded(path, limit, **kwargs):
            self.assertNotIn(path, (signature,menu))
            return original(path,limit,**kwargs)
        with patch.object(self.trust,'read',side_effect=bounded):
            observed = self.upgrade.stock_observation(root,self.web)
        self.assertEqual(observed['signatures']['framework'],'unavailable')
        self.assertEqual(observed['menu'],'unavailable')
        (self.web/'admin/modules/framework/module.xml').write_bytes(
            b'<?xml version="1.0" encoding="missing-codec"?><module><version>17.0.34</version></module>')
        self.assertIsNone(self.upgrade.stock_observation(root,self.web)['versions']['framework'])

    def test_successful_resigning_does_not_repeat_for_every_external_signature_rewrite(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        menu = self.web/'admin/views/menu_items.php'
        menu.write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        signature = self.web/'admin/modules/framework/module.sig'
        def step(action, minute):
            return self.stock_step(root, action, web=self.web, packages=self.offline,
                                                  now=1700000000 + 60*minute)
        for action in ('reserve','reconcile','complete'): step(action,0)
        signature.write_bytes(b'first replacement')
        self.assertEqual(step('probe',1),'due')
        for action in ('reserve','reconcile','complete'): step(action,1)
        for minute in range(2,61):
            signature.write_text('different replacement number ' + str(minute))
            self.assertEqual(step('probe',minute),'waiting')
        self.assertEqual(step('probe',61),'due')
        self.next_framework()
        self.assertEqual(step('probe',2),'due')

    def test_maintenance_retains_reviewed_missing_branding_and_throttles_failed_reconciliation(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        data,_ = self.trust.load(root, 'framework')
        data['files']['sls-branding/footer.php'] = {'sha256': self.trust.digest(b'reviewed customization'),
            'target': 'admin/modules/framework/sls-branding/footer.php'}
        self.trust.store_manifest(root, data, json.dumps(data).encode())
        previous = (root/'framework.active.json').read_bytes()
        self.next_framework()
        def step(action, now=1700000000):
            return self.stock_step(root, action, web=self.web, packages=self.offline, now=now)
        step('reserve')
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'review'):
            step('reconcile')
        self.assertEqual(step('failed'),'failed')
        report = json.loads((root/'stock-maintenance-review.json').read_text())
        self.assertIn('sls-branding/footer.php', [row['path'] for row in report['differences']])
        self.assertEqual((root/'framework.active.json').read_bytes(), previous)
        self.assertEqual(step('probe',1700000060),'waiting')
        self.assertEqual(step('probe',1700086399),'waiting')
        self.assertEqual(step('probe',1700086400),'due')
        self.assertFalse((root/'stock-maintenance-work').exists())

    def test_only_original_vendor_signature_on_entire_approved_stock_layout_can_be_reused(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        self.next_framework({'module.sig': b'signature from independent whole vendor package'})
        self.upgrade.reconcile_stock(self.root/'vendor-review', root, web=self.web, packages=self.offline)
        signature = self.web/'admin/modules/framework/module.sig'
        self.assertTrue(self.trust.reusable_framework_signature(root, self.web))
        signature.write_bytes(b'replaced locally')
        self.assertFalse(self.trust.reusable_framework_signature(root, self.web))
        signature.write_bytes(b'signature from independent whole vendor package')
        data,_ = self.trust.load(root, 'framework')
        data['files']['sls-branding/footer.php'] = {'sha256': self.trust.digest(b'reviewed'),
            'target': 'admin/modules/framework/sls-branding/footer.php'}
        self.trust.store_manifest(root, data, json.dumps(data).encode())
        self.assertFalse(self.trust.reusable_framework_signature(root, self.web))

    def test_explicit_reconciliation_rearms_a_verified_same_version_repair(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        menu = self.web/'admin/views/menu_items.php'
        menu.write_bytes(self.stock['framework'][self.upgrade.MENU_NAME])
        relative = 'sls-branding/footer.php'
        footer = self.web/'admin/modules/framework'/relative
        body = b'previously approved site footer'
        data, _ = self.trust.load(root, 'framework')
        data['files'][relative] = {'target': 'admin/modules/framework/'+relative, 'sha256': self.trust.digest(body)}
        self.trust.store_manifest(root, data, json.dumps(data).encode())
        reference = (root/'framework.active.json').read_bytes()
        def step(action):
            return self.stock_step(root, action, web=self.web, packages=self.offline, now=1700000000)
        def review(name, **options):
            return self.upgrade.reconcile_stock(self.root/name, root, web=self.web, packages=self.offline, **options)
        step('reserve')
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'review'):
            step('reconcile')
        self.assertEqual(step('failed'), 'failed')
        receipt = root/'stock-maintenance.json'
        report = root/'stock-maintenance-review.json'
        failed_state, differences = receipt.read_bytes(), report.read_bytes()
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed'):
            review('operator-review-before-restoration', schedule_signature_check=True)
        self.assertEqual(receipt.read_bytes(), failed_state)
        footer.parent.mkdir(); footer.write_bytes(body)
        self.assertEqual(review('offline-uninstall-preflight')['changed_modules'], [])
        self.assertEqual(step('probe'), 'waiting')
        result = review('operator-review-after-restoration', schedule_signature_check=True)
        self.assertEqual(result['changed_modules'], [])
        self.assertEqual((root/'framework.active.json').read_bytes(), reference)
        self.assertEqual(report.read_bytes(), differences)
        self.assertEqual(step('probe'), 'due')
        for action in ('reserve', 'reconcile', 'complete'):
            step(action)
        self.assertEqual(step('probe'), 'current')
        self.assertFalse(report.exists())

    def test_stock_maintenance_reclaims_its_interrupted_download_without_discarding_operator_files(self):
        self.seed_current_stock_cache()
        root = self.args.trust_root
        self.next_framework()
        work = root/'stock-maintenance-work'
        def step(action):
            return self.stock_step(root, action, web=self.web, packages=self.offline)
        step('reserve')
        def interrupt(workspace,*args,**kwargs):
            (workspace/'framework-17.0.6.tgz.gpg').write_bytes(b'partial')
            raise SystemExit(1)
        # Model process loss after the workspace was recorded and before its
        # normal cleanup. A second cron tick has to resume from signed sources.
        with patch.object(self.upgrade,'reconcile_stock',side_effect=interrupt), \
                patch.object(self.upgrade.shutil,'rmtree'), self.assertRaises(SystemExit):
            step('reconcile')
        self.assertTrue(work.is_dir())
        extra = work/'operator-note'
        extra.write_bytes(b'preserve me')
        step('reserve')
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'workspace'):
            step('reconcile')
        self.assertEqual(extra.read_bytes(),b'preserve me')
        extra.unlink()
        step('reserve')
        step('reconcile')
        step('complete')
        self.assertFalse(work.exists())

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

    def test_preserve_previously_reviewed_stock_omission_on_unchanged_vendor_base(self):
        entry = {'sha256': self.trust.digest(b'upstream body'), 'target': 'admin/modules/framework/vendor.php'}
        base = {'files': {'vendor.php': entry}}
        approved = {'files': {}}
        candidate = {'module': 'framework', 'source': {}, 'files': {'vendor.php': dict(entry)}}
        self.upgrade.carry_reviewed_overlays(approved, base, candidate)
        self.assertNotIn('vendor.php', candidate['files'])
        self.trust.check_reviewed_omissions(candidate, self.web)
        target = self.web / entry['target']
        target.write_bytes(b'reappeared')
        with self.assertRaisesRegex(self.trust.TrustError, 'previously omitted stock file is present'):
            self.trust.check_reviewed_omissions(candidate, self.web)
        changed = {'files': {'vendor.php': {**entry, 'sha256': self.trust.digest(b'updated vendor body')}}}
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'changed upstream'):
            self.upgrade.carry_reviewed_overlays(approved, base, changed)

    def test_framework_migration_keeps_publisher_menu_and_matching_rollback(self):
        self.prepare()
        name = self.upgrade.MENU_NAME
        clean = self.stock['framework'][name]
        approvals = json.loads((self.workspace / 'approvals.json').read_bytes())
        self.assertEqual(approvals['approved']['framework']['files'][name]['sha256'], self.trust.digest(clean))
        self.assertNotIn(name, approvals['approved']['framework']['uninstall']['replace'])
        rollback = json.loads((self.workspace / 'previous-web-approval.json').read_bytes())
        self.assertEqual(rollback['framework']['files'][name]['sha256'], self.trust.digest(self.upgrade.menu_overlay(clean)))
        # Also cover installations with a protected legacy approval at the same version.
        legacy = approvals['approved']['framework']
        legacy['uninstall']['replace'][name] = self.trust.digest(clean)
        legacy['files'][name]['sha256'] = rollback['framework']['files'][name]['sha256']
        self.trust.store_manifest(self.args.trust_root, legacy, json.dumps(legacy).encode())
        self.args.workspace = self.root / 'review-enrolled'
        self.prepare()
        enrolled = json.loads((self.args.workspace / 'framework.json').read_bytes())
        self.assertEqual(enrolled['files'][name]['sha256'], self.trust.digest(clean))
        self.assertNotIn(name, enrolled['uninstall']['replace'])
        menu = self.web / 'admin/views/menu_items.php'
        menu.write_bytes(menu.read_bytes() + b'// external edit')
        self.args.workspace = self.root / 'review-third-party-edit'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed PBX differences'):
            self.prepare()

    def test_framework_with_new_native_menu_path_never_mutates_the_obsolete_location(self):
        data = {'files': {}, 'uninstall': {'remove': [], 'replace': {}}}
        previous = {'files': {}}
        menu = self.web / 'admin/views/menu_items.php'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'unreviewed'):
            self.upgrade.prepare_native_menu(data, previous, self.web)
        menu.unlink()
        self.upgrade.prepare_native_menu(data, previous, self.web)
        self.assertFalse(menu.exists())
        self.assertEqual(previous['files'], {})

    def test_new_signed_layout_can_retire_obsolete_menu_and_spinner_assets(self):
        contents = {'module.xml': b'<module/>', 'module.sig': b'signed package inventory'}
        source = {'kind': 'reviewed-upstream-and-overlays', 'archive_sha256': '0' * 64,
                  'upstream_signer': self.upgrade.UPSTREAM_SIGNER}
        data, prior = self.upgrade.upstream_inventory(contents, source, 'framework', '17.0.99', {}, {}, self.web)
        self.assertEqual(set(data['files']), {'module.xml'})
        self.assertNotIn(self.upgrade.MENU_NAME, prior['files'])
        self.assertEqual(data['source']['vendor_signature']['sha256'], self.trust.digest(contents['module.sig']))

    def test_framework_accepts_changed_vendor_menu_without_legacy_sort_function(self):
        name = self.upgrade.MENU_NAME
        vendor = b'<?php // new vendor markup with no old sorting conditional'
        self.next_framework({name: vendor})
        self.prepare()
        approved = json.loads((self.workspace / 'framework.json').read_bytes())
        self.assertEqual(approved['files'][name]['sha256'], self.trust.digest(vendor))

    def test_installer_carries_reviewed_branding_across_framework_update(self):
        self.seed_current_stock_cache()
        self.next_framework()
        old, _ = self.trust.load(self.args.trust_root, 'framework')
        name = 'sls-branding/footer.php'
        relative = 'admin/modules/framework/' + name
        expected = {'target': relative, 'sha256': self.trust.digest(b'reviewed footer')}
        old['files'][name] = expected
        self.trust.store_manifest(self.args.trust_root, old, json.dumps(old).encode())
        self.args.workspace = self.root / 'updated-without-footer'
        with self.assertRaisesRegex(self.upgrade.UpgradeError, 'Unreviewed PBX differences'):
            self.prepare()
        report = json.loads((self.args.workspace / 'review-required.json').read_bytes())
        self.assertIn(name, {issue['path'] for issue in report['differences']})
        self.assertEqual(self.trust.load(self.args.trust_root, 'framework')[0], old)
        footer = self.web / relative
        footer.parent.mkdir()
        footer.write_bytes(b'reviewed footer')
        self.args.workspace = self.root / 'updated-with-reviewed-footer'
        self.prepare()
        updated = json.loads((self.args.workspace / 'framework.json').read_bytes())
        self.assertEqual(updated['files'][name], expected)

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

    def native_framework_companion(self, version='17.0.33.4', present=True, body=None):
        """Vendor manual-copy shape; the real GPG package supplies expectations."""
        name = 'amp_conf/etc/init.d/freepbx.init'
        vendor = (ROOT / 'tools/fixtures/framework-native-init.txt').read_bytes()
        self.assertEqual(len(vendor), 1619)
        self.assertEqual(self.trust.digest(vendor), '8d6af9b7278b78ce4d10faf142a6e62ae0d72e746d0f303cce429f6ca768cbe0')
        contents = dict(self.stock['framework'])
        contents['module.xml'] = ('<module><rawname>framework</rawname><version>' + version + '</version></module>').encode()
        contents[name] = vendor if body is None else body
        plain = self.root / ('framework-native-' + version + '.tgz')
        package(plain, 'framework', contents)
        signed = self.offline / ('framework-' + version + '.tgz.gpg')
        subprocess.run(self.gpg_command + ['--yes', '--output', str(signed), '--sign', str(plain)],
                       check=True, capture_output=True, timeout=20)
        module = self.web / 'admin/modules/framework'
        (module / 'module.xml').write_bytes(contents['module.xml'])
        target = module / name
        if present:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents[name]); target.chmod(0o664)
        return target

    def test_signed_native_retained_init_is_compared_and_preserved_for_qualified_versions(self):
        root_init = self.fs / 'etc/init.d/freepbx'
        root_init.parent.mkdir(parents=True); root_init.write_bytes(b'independent root init must not change')
        root_init.chmod(0o755)
        for version in sorted(self.upgrade.NATIVE_FRAMEWORK_VERSIONS):
            with self.subTest(version=version):
                target = self.native_framework_companion(version)
                self.workspace = self.args.workspace = self.root / ('native-review-' + version)
                before = target.read_bytes(); root_before = root_init.read_bytes()
                accepted = True
                try:
                    self.prepare()
                except self.upgrade.UpgradeError:
                    accepted = False
                    report = json.loads((self.workspace / 'review-required.json').read_bytes())
                    self.assertEqual(report['differences'], [{'module': 'framework', 'path': 'amp_conf/etc/init.d/freepbx.init', 'reason': 'unexpected file'}])
                self.assertTrue(accepted, 'Authenticated vendor manual-copy init was refused as an unexpected file')
                approvals = json.loads((self.workspace / 'approvals.json').read_bytes())
                for phase in ('prior', 'approved'):
                    entry = approvals[phase]['framework']['files']['amp_conf/etc/init.d/freepbx.init']
                    self.assertEqual(entry, {'sha256': self.trust.digest(before), 'target': 'admin/modules/framework/amp_conf/etc/init.d/freepbx.init'})
                self.assertEqual(target.read_bytes(), before)
                self.assertEqual(root_init.read_bytes(), root_before)
                self.assert_preserved()

    def test_absent_native_init_is_not_required_or_copied(self):
        target = self.native_framework_companion(present=False)
        root_init = self.fs / 'etc/init.d/freepbx'
        self.prepare()
        data = json.loads((self.workspace / 'framework.json').read_bytes())
        self.assertNotIn('amp_conf/etc/init.d/freepbx.init', data['files'])
        self.assertNotIn('native_framework_source_files', data['source'])
        self.assertFalse(target.exists()); self.assertFalse(root_init.exists())
        self.assert_preserved()

    def test_changed_native_companion_never_becomes_the_expected_hash(self):
        target = self.native_framework_companion()
        vendor = target.read_bytes(); changed = b'!' + vendor[1:]; target.write_bytes(changed)
        with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
        report = json.loads((self.workspace / 'review-required.json').read_bytes())
        self.assertIn({'module': 'framework', 'path': 'amp_conf/etc/init.d/freepbx.init',
                       'reason': 'bytes differ from signed/reviewed source'}, report['differences'])
        package_path = self.offline / 'framework-17.0.33.4.tgz.gpg'
        contents, source = self.upgrade.upstream_contents(package_path, 'framework', '17.0.33.4', self.workspace)
        data, prior = self.upgrade.upstream_inventory(contents, source, 'framework', '17.0.33.4', self.new, self.old, self.web)
        self.assertEqual(data['files']['amp_conf/etc/init.d/freepbx.init']['sha256'], self.trust.digest(vendor))
        self.assertNotEqual(data['files']['amp_conf/etc/init.d/freepbx.init']['sha256'], self.trust.digest(changed))
        self.assertEqual(target.read_bytes(), changed); self.assert_preserved()

    def test_native_companion_unknown_source_version_hash_and_other_paths_stay_unreviewed(self):
        vendor = (ROOT / 'tools/fixtures/framework-native-init.txt').read_bytes()
        for fault in ('unknown version', 'different authenticated bytes', 'another retained file'):
            with self.subTest(fault=fault):
                target = self.native_framework_companion('17.0.99' if fault == 'unknown version' else '17.0.33.4',
                                                         body=b'!' + vendor[1:] if fault == 'different authenticated bytes' else vendor)
                extra = target.parent / 'other.init'
                if fault == 'another retained file': extra.write_bytes(vendor)
                self.workspace = self.args.workspace = self.root / ('refusal-' + fault.replace(' ', '-'))
                with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
                self.assertEqual(target.read_bytes(), b'!' + vendor[1:] if fault == 'different authenticated bytes' else vendor)
                if extra.exists(): extra.unlink()
                self.assert_preserved()

    def test_native_companion_metadata_rejects_execute_links_and_foreign_identity(self):
        target = self.native_framework_companion(); vendor = target.read_bytes()
        account = pwd.getpwnam('asterisk')
        for fault in ('execute', 'other writable', 'symlink', 'hardlink', 'foreign owner', 'foreign group'):
            with self.subTest(fault=fault):
                target.unlink(); target.write_bytes(vendor); target.chmod(0o664)
                alias = target.parent / 'companion-alias'
                if fault == 'execute': target.chmod(0o755)
                elif fault == 'other writable': target.chmod(0o666)
                elif fault == 'symlink':
                    alias.write_bytes(vendor); target.unlink(); target.symlink_to(alias.name)
                elif fault == 'hardlink': os.link(target, alias)
                elif fault == 'foreign owner': os.chown(target, account.pw_uid + 10000, account.pw_gid)
                elif fault == 'foreign group': os.chown(target, account.pw_uid, account.pw_gid + 10000)
                self.workspace = self.args.workspace = self.root / ('metadata-' + fault.replace(' ', '-'))
                with self.assertRaises((self.upgrade.UpgradeError, self.trust.TrustError, OSError)): self.prepare()
                self.assert_preserved()
                if alias.exists(): alias.unlink()

    def test_native_companion_accepts_exact_canonical_native_owner_without_chown(self):
        target = self.native_framework_companion(); account = pwd.getpwnam('asterisk')
        os.chown(target, account.pw_uid, account.pw_gid); target.chmod(0o664)
        before = target.stat()
        self.prepare()
        after = target.stat()
        self.assertEqual((before.st_uid, before.st_gid, before.st_mode, before.st_ino),
                         (after.st_uid, after.st_gid, after.st_mode, after.st_ino))
        self.assert_preserved()

    def test_native_companion_restrictive_readable_modes_are_preserved(self):
        target = self.native_framework_companion()
        for mode in (0o600, 0o640, 0o444, 0o400):
            with self.subTest(mode=oct(mode)):
                target.chmod(mode)
                self.workspace = self.args.workspace = self.root / ('restrictive-' + oct(mode))
                accepted = True
                try: self.prepare()
                except self.upgrade.UpgradeError: accepted = False
                self.assertTrue(accepted, 'Authenticated owner-readable permission subset was refused')
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                self.assert_preserved()

    def test_native_companion_extended_ACL_cannot_add_a_foreign_writer(self):
        target = self.native_framework_companion(); account = pwd.getpwnam('asterisk')
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, permissions, identity) for tag, permissions, identity in (
            (1, 6, 0xffffffff), (2, 6, account.pw_uid + 10000), (4, 6, 0xffffffff),
            (16, 6, 0xffffffff), (32, 4, 0xffffffff)))
        try: os.setxattr(target, 'system.posix_acl_access', acl)
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.ENOTSUP): self.skipTest('Namespace filesystem cannot represent POSIX access ACLs')
            raise
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o664)
        with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
        self.assertEqual(os.getxattr(target, 'system.posix_acl_access'), acl)
        self.assert_preserved()

    def test_native_companion_uncertain_ACL_inspection_fails_closed(self):
        self.native_framework_companion()
        for error_code in (errno.ENOTSUP, errno.EIO, errno.EPERM, errno.ENOSYS):
            with self.subTest(error_code=error_code):
                self.workspace = self.args.workspace = self.root / ('ACL-query-' + str(error_code))
                def unavailable(descriptor, name):
                    self.assertIsInstance(descriptor, int)
                    self.assertEqual(name, 'system.posix_acl_access')
                    raise OSError(error_code, 'controlled ACL inspection failure')
                with patch.object(self.upgrade.os, 'getxattr', side_effect=unavailable):
                    with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
                self.assert_preserved()

    def test_native_companion_schema_and_role_are_rechecked_on_later_comparison(self):
        target = self.native_framework_companion(); self.prepare()
        approvals = json.loads((self.workspace / 'approvals.json').read_bytes())
        data = approvals['approved']['framework']; prior = approvals['prior']['framework']
        for fault in ('null projection', 'empty projection', 'boolean schema', 'floating byte count', 'unknown projection path', 'wrong digest', 'wrong target', 'unknown version', 'wrong signer'):
            with self.subTest(fault=fault):
                bad = copy.deepcopy(data)
                projection = bad['source']['native_framework_source_files']
                if fault == 'null projection': bad['source']['native_framework_source_files'] = None
                elif fault == 'empty projection': bad['source']['native_framework_source_files'] = {}
                elif fault == 'boolean schema': projection['schema'] = True
                elif fault == 'floating byte count': projection['files']['amp_conf/etc/init.d/freepbx.init']['bytes'] = 1619.0
                elif fault == 'unknown projection path': projection['files']['extra.init'] = dict(next(iter(projection['files'].values())))
                elif fault == 'wrong digest': bad['files']['amp_conf/etc/init.d/freepbx.init']['sha256'] = 'f' * 64
                elif fault == 'wrong target': bad['files']['amp_conf/etc/init.d/freepbx.init']['target'] = 'etc/init.d/freepbx'
                elif fault == 'unknown version': bad['version'] = '17.0.99'
                elif fault == 'wrong signer': bad['source']['upstream_signer'] = 'F' * 40
                with self.assertRaisesRegex(self.upgrade.UpgradeError, 'companion'):
                    self.upgrade.compare_stock(bad, prior, self.web, self.new)
        target.chmod(0o755)
        differences = self.upgrade.compare_stock(data, prior, self.web, self.new)
        self.assertIn({'module': 'framework', 'path': 'amp_conf/etc/init.d/freepbx.init',
                       'reason': 'unsafe, missing or changing file'}, differences)
        self.assert_preserved()

    def test_existing_framework_enrollment_is_not_extended_with_a_new_native_copy(self):
        target = self.native_framework_companion(present=False); self.prepare()
        data = json.loads((self.workspace / 'framework.json').read_bytes())
        self.trust.store_manifest(self.args.trust_root, data, json.dumps(data).encode())
        pointer = self.args.trust_root / 'framework.active.json'; before = pointer.read_bytes()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / 'tools/fixtures/framework-native-init.txt').read_bytes()); target.chmod(0o664)
        self.workspace = self.args.workspace = self.root / 'enrolled-companion-review'
        with self.assertRaises(self.upgrade.UpgradeError): self.prepare()
        self.assertEqual(pointer.read_bytes(), before)
        for name, body in self.preserved.items(): self.assertEqual((self.data / name).read_bytes(), body)

    def test_historical_independent_companion_approval_keeps_authority_without_new_tags(self):
        target = self.native_framework_companion(); self.prepare()
        old = json.loads((self.workspace / 'framework.json').read_bytes())
        del old['source']['native_framework_source_files']
        vendor = target.read_bytes()
        for kind, approved in [('vendor', vendor), ('custom', b'independently reviewed historical customization\n')]:
            with self.subTest(kind=kind):
                target.write_bytes(approved); target.chmod(0o755 if kind == 'custom' else 0o664)
                old['files']['amp_conf/etc/init.d/freepbx.init']['sha256'] = self.trust.digest(approved)
                body = json.dumps(old).encode(); self.trust.parse_manifest(body)
                self.trust.store_manifest(self.args.trust_root, old, body)
                before = {str(path.relative_to(self.args.trust_root)): path.read_bytes()
                          for path in self.args.trust_root.rglob('*') if path.is_file()}
                self.workspace = self.args.workspace = self.root / ('historical-independent-' + kind)
                accepted = True
                try: self.prepare()
                except self.upgrade.UpgradeError: accepted = False
                self.assertTrue(accepted, 'An independently reviewed existing entry was refused solely for lacking the new projection tag')
                after = {str(path.relative_to(self.args.trust_root)): path.read_bytes()
                         for path in self.args.trust_root.rglob('*') if path.is_file()}
                self.assertEqual(after, before)
                self.assertEqual(target.read_bytes(), approved)
                self.assertNotIn('native_framework_source_files', self.trust.load(self.args.trust_root, 'framework')[0]['source'])
                for name, value in self.preserved.items(): self.assertEqual((self.data / name).read_bytes(), value)

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
            previous_files = dict(self.stock[name])
            previous_files['module.xml'] = previous_files['module.xml'].replace(b'17.0.5', b'17.0.4')
            previous_archive = self.root / (name + '-previous.tgz')
            package(previous_archive, name, previous_files)
            signed = self.offline / (name + '-17.0.4.tgz.gpg')
            subprocess.run(self.gpg_command + ['--output', str(signed), '--sign', str(previous_archive)],
                           check=True, capture_output=True, timeout=20)
            old['source']['archive_sha256'] = self.trust.digest(previous_archive.read_bytes())
            old['files']['module.xml']['sha256'] = self.trust.digest(previous_files['module.xml'])
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

    def check_spinner_topology_change(self, previous_alias):
        spinner = self.web / 'admin/images/spinner.gif'
        core = self.web / 'admin/modules/core/images/spinner.gif'
        core.parent.mkdir(parents=True)
        stock = self.stock['framework'][self.upgrade.SPINNER]
        core.write_bytes(stock)
        if previous_alias:
            spinner.unlink()
            spinner.symlink_to(core)
        self.seed_current_stock_cache()
        original = self.trust.load(self.args.trust_root, 'framework')[0]
        self.assertEqual('link_target' in original['files'][self.upgrade.SPINNER], previous_alias)
        spinner.unlink()
        self.next_framework()
        if not previous_alias:
            spinner.unlink()
            spinner.symlink_to(core)
        review = self.root / 'changed-spinner'
        result = self.upgrade.reconcile_stock(review, self.args.trust_root, web=self.web, packages=self.offline)
        self.assertEqual(result['changed_modules'], ['framework'])
        current = self.trust.load(self.args.trust_root, 'framework')[0]
        self.assertEqual('link_target' in current['files'][self.upgrade.SPINNER], not previous_alias)
        self.assertEqual(current['files'][self.upgrade.SPINNER]['sha256'], self.trust.digest(stock))
        self.assertEqual(spinner.is_symlink(), not previous_alias)
        spinner.write_bytes(b'changed after update')
        self.assertIn(self.upgrade.SPINNER, {i['path'] for i in self.upgrade.compare_stock(current, current, self.web, self.old)})

    def test_signed_framework_transition_from_core_alias_to_regular_vendor_gif(self):
        self.check_spinner_topology_change(previous_alias=True)

    def test_signed_framework_transition_from_regular_vendor_gif_to_core_alias(self):
        self.check_spinner_topology_change(previous_alias=False)

    def test_reviewed_spinner_digest_still_survives_if_vendor_base_is_identical(self):
        name = self.upgrade.SPINNER
        target = 'admin/images/spinner.gif'
        base = {'files': {name: {'target': target, 'sha256': self.trust.digest(b'stock')}}}
        reviewed = {'module': 'framework', 'files': {name: {'target': target, 'sha256': self.trust.digest(b'branded')}}}
        candidate = {'files': {name: dict(base['files'][name])}}
        self.upgrade.carry_reviewed_overlays(reviewed, base, candidate)
        self.assertEqual(candidate['files'][name], reviewed['files'][name])

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
