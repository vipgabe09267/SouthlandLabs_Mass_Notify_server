#!/usr/bin/python3
"""Isolated behavioral regressions for safe update/removal/signature failures."""
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]


class SafeLifecycle(unittest.TestCase):
    def test_authenticated_installer_runs_from_noexec_scratch_without_remounting_it(self):
        # Restoring direct execution of a downloaded script breaks this behavior.
        source = (ROOT / 'slsmassnotifyserver/bin/sls_mass_notify_update.sh').read_text()
        start = source.index('verified_sha256="$(sha256sum ')
        end = source.index('log "Automatic update completed', start)
        with tempfile.TemporaryDirectory(prefix='sls-v020-noexec-', dir='/run') as name:
            root = Path(name)
            scratch = root / 'scratch';scratch.mkdir()
            subprocess.run(['/bin/mount', '-t', 'tmpfs', '-o', 'noexec,nosuid,nodev,size=2m',
                            'sls-v020-noexec', str(scratch)], check=True, capture_output=True)
            try:
                installer = scratch / 'installer.sh'
                marker = root / 'verified-executed'
                installer.write_text('#!/bin/bash\nprintf "%s" "$SLS_MASS_NOTIFY_TGZ" > "$V020_MARKER"\n')
                installer.chmod(0o700)
                package = root / 'package';package.write_bytes(b'exact authenticated fixture package')
                program = '''set -euo pipefail
tmp_script="$1"; release_package="$2"; LOG_FD=2; latest=0.2.0-beta
log() { :; }; fail_update() { exit "${3:-1}"; }
''' + source[start:end]
                result = subprocess.run(['/bin/bash', '-c', program, 'fixture', str(installer), str(package)],
                                        capture_output=True, text=True, timeout=10,
                                        env={**os.environ, 'V020_MARKER': str(marker)})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(marker.read_text(), str(package))
                # The mount remains noexec; direct-exec denial is checked without
                # ever permitting that process to run on a changed mount.
                with self.assertRaises(PermissionError):
                    subprocess.run([str(installer)], capture_output=True, timeout=3)
            finally:
                subprocess.run(['/bin/umount', str(scratch)], check=True, capture_output=True)

    def observe_signature_restore(self, readonly):
        with tempfile.TemporaryDirectory(prefix='sls-v020-signature-', dir='/run') as name:
            root = Path(name)
            web = root / 'web';web.mkdir()
            subprocess.run(['/bin/mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,size=2m',
                            'sls-v020-signature', str(web)], check=True, capture_output=True)
            try:
                module = web / 'admin/modules/framework';module.mkdir(parents=True)
                original = b'exact inert old signature\n'
                candidate = b'inert rejected candidate\n'
                (module / 'module.sig').write_bytes(original)
                work = root / 'work';work.mkdir(mode=0o700)
                (work / 'module.sig.candidate').write_bytes(candidate)
                helper = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py'
                # The following preparation step is deliberately inert; its
                # failure occurs only after the actual signature publication.
                program = '''source "$1"
MODULE=framework; FREEPBX_WEB_ROOT="$2"; FREEPBX_WEB_USER=asterisk
MODULE_DIR="$FREEPBX_WEB_ROOT/admin/modules/$MODULE"
TRUST_HELPER="$3"; WORKDIR="$4"; V020_READONLY="$5"
prepare_freepbx_gpg_home() {
 if [ "$V020_READONLY" = 1 ]; then /bin/mount -o remount,ro "$FREEPBX_WEB_ROOT" || return 90; fi
 return 19
}
if publish_candidate_transactionally; then exit 97; fi
exit 19
'''
                result = subprocess.run(['/bin/bash', '-c', program, 'fixture',
                                         str(ROOT / 'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh'),
                                         str(web), str(helper), str(work), '1' if readonly else '0'],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 19, result.stderr)
                if readonly:
                    self.assertEqual((module / 'module.sig').read_bytes(), candidate, result.stderr)
                    self.assertTrue(work.is_dir(), 'failed restoration discarded its exact beforeimage')
                    self.assertEqual((work / 'module.sig.previous').read_bytes(), original)
                    self.assertIn(str(work), result.stderr)
                else:
                    self.assertEqual((module / 'module.sig').read_bytes(), original)
                    self.assertFalse(work.exists())
            finally:
                subprocess.run(['/bin/umount', str(web)], check=True, capture_output=True)

    def test_failed_signature_restoration_preserves_beforeimage_and_reports_its_path(self):
        self.observe_signature_restore(True)

    def test_successfully_restored_signature_cleans_only_finished_workspace(self):
        self.observe_signature_restore(False)

    def test_malformed_owned_blocks_refuse_during_check_without_mutation(self):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(prefix='sls-v020-block-', dir='/run') as name:
            root = Path(name);root.chmod(0o755)
            directory = root / 'managed';directory.mkdir(mode=0o755)
            os.chown(directory, account.pw_uid, account.pw_gid)
            for index, body in enumerate((
                'keep\n; BEGIN V020 owned\nunclosed\n',
                'keep\n; END V020 owned\n',
                '; BEGIN V020 owned\n; BEGIN V020 owned\n; END V020 owned\n')):
                path = directory / ('case' + str(index))
                path.write_text(body);os.chown(path, account.pw_uid, account.pw_gid);path.chmod(0o640)
                before = path.stat()
                result = subprocess.run(['/bin/bash', '-c',
                    'source "$1"; rewrite_managed_text_file "$2" managed-block "V020 owned" check',
                    'fixture', str(ROOT / 'tools/uninstall_release.sh'), str(path)],
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, 'ambiguous owned block passed pre-teardown check')
                self.assertEqual(path.read_text(), body)
                self.assertEqual((path.stat().st_ino, stat.S_IMODE(path.stat().st_mode)), (before.st_ino, 0o640))

    def test_complete_owned_block_preserves_unrelated_text(self):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(prefix='sls-v020-block-complete-', dir='/run') as name:
            root=Path(name);root.chmod(0o755);directory=root/'managed';directory.mkdir(mode=0o755)
            os.chown(directory,account.pw_uid,account.pw_gid)
            path=directory/'good.conf';path.write_text('before\n; BEGIN V020 owned\nowned\n; END V020 owned\nafter\n')
            os.chown(path,account.pw_uid,account.pw_gid);path.chmod(0o640)
            result=subprocess.run(['/bin/bash','-c',
                'source "$1"; rewrite_managed_text_file "$2" managed-block "V020 owned"',
                'fixture',str(ROOT/'tools/uninstall_release.sh'),str(path)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(path.read_text(),'before\nafter\n')


if __name__ == '__main__':
    unittest.main()
