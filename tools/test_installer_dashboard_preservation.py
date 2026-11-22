#!/usr/bin/python3
"""Private observation of legacy Overview restoration in automatic UI repair.

The real PHP repair method, safe reader, atomic writer, and cleanup helpers run
as Asterisk over inert private files. Only fixed path prefixes are relocated.
Dashboard hook discovery and copying the two unrelated widgets are fixture
boundaries; no FreePBX bootstrap, database, signing, or installer is executed.
Run only by the root audit controller through the official namespace wrapper.
"""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'slsmassnotifyserver/Slsmassnotifyserver.class.php').read_text()


def method(name):
    found = re.search(r'^\t(?:private|public|protected) function ' + re.escape(name)
                      + r'\([^\n]*\)[^\n]*\n\t\{\n.*?^\t\}', SOURCE,
                      re.MULTILINE | re.DOTALL)
    if found is None:
        raise RuntimeError('Cannot locate the unchanged product method: ' + name)
    return found.group(0)


class DashboardCurrentSourcePreservation(unittest.TestCase):
    def observe(self, saved_legacy, hook_failure):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(prefix='sll-audit-final-dashboard-', dir='/run') as temporary:
            base = Path(temporary)
            base.chmod(0o755)
            web = base / 'web'
            data = base / 'data'
            overview = web / 'admin/modules/dashboard/sections/Overview.class.php'
            backup = data / 'backups/dashboard/Overview.class.php'
            view = web / 'admin/modules/dashboard/views/sections'
            for destination in (overview.parent, backup.parent, view):
                destination.mkdir(parents=True, exist_ok=True)
            for directory in [web, data, *web.rglob('*'), *data.rglob('*')]:
                if directory.is_dir():
                    os.chown(directory, account.pw_uid, account.pw_gid)
                    directory.chmod(0o755)
            current = b'<?php /* independently updated Dashboard: new vendor Overview */\n'
            legacy = b'<?php /* older saved Dashboard: legacy vendor Overview */\n'
            overview.write_bytes(current)
            os.chown(overview, account.pw_uid, account.pw_gid)
            overview.chmod(0o644)
            if saved_legacy:
                backup.write_bytes(legacy)
                os.chown(backup, account.pw_uid, account.pw_gid)
                backup.chmod(0o600)
            selected = '\n'.join(method(name) for name in (
                'ensureDashboardWidget', 'readNativeBackupFile', 'readManagedTextFile',
                'writeManagedTextFile', 'unlinkNamedFileIfIdentity',
                'removeLegacyDashboardOverviewPatch'))
            selected = selected.replace('/var/www/html', str(web))
            # The real whitelist remains in effect, with its fixed web prefix
            # relocated to the same private tree as the fixed target path.
            fixture = '''<?php
class AuditDashboardRestore {
 const PLUGIN_DATA_DIR = DATA_VALUE;
 public function run() { $this->ensureDashboardWidget(); }
 private function copyRuntimeFile($source,$target,$mode=0644,$overwrite=true) {
  $this->writeManagedTextFile($target,"<?php /* inert current widget */\\n",$mode);
 }
 private function refreshDashboardHookIndex() {
  if (getenv('AUDIT_HOOK_FAILURE') === '1') { throw new \\RuntimeException('inert hook-discovery failure'); }
 }
 ACTUAL_METHODS
}
$failure = null;
try { (new AuditDashboardRestore)->run(); }
catch (\\Throwable $error) { $failure = $error->getMessage(); }
echo json_encode(['uid'=>posix_geteuid(),'failure'=>$failure]),"\\n";
'''.replace('DATA_VALUE', "'" + str(data) + "'").replace('ACTUAL_METHODS', selected)
            php = base / 'fixture.php'
            php.write_text(fixture)
            php.chmod(0o644)
            result = subprocess.run(['/usr/sbin/runuser', '-u', 'asterisk', '--',
                                     '/usr/bin/php', str(php)], capture_output=True,
                                    text=True, timeout=15,
                                    env={**os.environ, 'AUDIT_HOOK_FAILURE': '1' if hook_failure else '0'})
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed['uid'], account.pw_uid)
            self.assertEqual(observed['failure'], 'inert hook-discovery failure' if hook_failure else None)
            self.assertEqual(overview.read_bytes(), current, 'A stale saved backup must never replace the current native Dashboard source')
            self.assertEqual(backup.exists(), saved_legacy, 'Retain the original recovery evidence instead of deleting it')
            if saved_legacy: self.assertEqual(backup.read_bytes(), legacy)
            self.assertTrue((overview.parent / 'SlsMassNotifyAnnouncement.class.php').is_file())

    def test_stale_saved_overview_preserves_current_vendor_source_and_evidence(self):
        self.observe(True, False)

    def test_hook_failure_preserves_both_current_vendor_source_and_old_evidence(self):
        self.observe(True, True)

    def test_no_legacy_backup_preserves_unpatched_new_vendor_overview(self):
        self.observe(False, False)


if __name__ == '__main__':
    unittest.main()
