#!/usr/bin/python3
"""Known uninstall afterimages stay retryable without approving mixed native trees."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py'
spec = importlib.util.spec_from_file_location('partial_uninstall_trust', SOURCE)
TRUST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TRUST)


class PartialUninstall(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sll-partial-uninstall-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.store = self.base / 'trust'
        self.web = self.base / 'web'
        self.widgets = ['sections/SlsMassNotifyAnnouncement.class.php', 'views/sections/sls-mass-notify-announcement.php']
        self.module = self.web / 'admin/modules/dashboard'
        self.stock = {'module.xml': b'<module><version>17.0.33</version></module>',
                      'sections/Overview.class.php': b'unchanged independently reviewed native overview',
                      **{name: ('approved SLL widget ' + name).encode() for name in self.widgets}}
        for name, body in self.stock.items():
            path = self.module / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        self.enroll('dashboard', self.stock, {'remove': self.widgets, 'replace': {}})
        framework = {'module.xml': b'<module><version>17.0.33</version></module>'}
        path = self.web / 'admin/modules/framework'; path.mkdir(parents=True)
        (path / 'module.xml').write_bytes(framework['module.xml'])
        self.enroll('framework', framework, {'remove': [], 'replace': {}})

    def enroll(self, module, files, uninstall):
        data = {'schema': 1, 'module': module, 'version': '17.0.33',
                'source': {'kind': 'reviewed-upstream-and-overlays', 'archive_sha256': 'a' * 64},
                'files': {name: {'sha256': TRUST.digest(body), 'target': 'admin/modules/' + module + '/' + name}
                          for name, body in files.items()}, 'uninstall': uninstall}
        raw = (json.dumps(data) + '\n').encode()
        TRUST.store_manifest(self.store, data, raw)

    def invoke(self, *arguments):
        return subprocess.run(['/usr/bin/python3', '-I', str(SOURCE), '--root', str(self.store),
            'check', '--module', 'dashboard', '--web-root', str(self.web), *arguments],
            capture_output=True, text=True, timeout=5)

    def test_one_of_two_exact_widgets_removed_allows_explicit_teardown_progress_only(self):
        before = (self.store / 'dashboard.active.json').read_bytes()
        for name in self.widgets:
            with self.subTest(name=name):
                (self.module / name).unlink()
                try:
                    self.assertNotEqual(self.invoke().returncode, 0)
                    self.assertNotEqual(self.invoke('--uninstalled').returncode, 0)
                    result = self.invoke('--uninstalling')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((self.store / 'dashboard.active.json').read_bytes(), before)
                finally:
                    (self.module / name).write_bytes(self.stock[name])

    def test_unknown_changes_links_missing_native_and_extra_files_still_refuse(self):
        (self.module / self.widgets[0]).unlink()
        target = self.module / self.widgets[1]
        for operation in ('changed_widget', 'missing_native', 'extra', 'link'):
            with self.subTest(operation=operation):
                if operation == 'changed_widget': target.write_bytes(b'unreviewed widget')
                elif operation == 'missing_native': (self.module / 'sections/Overview.class.php').unlink()
                elif operation == 'extra': (self.module / 'extra.php').write_bytes(b'unreviewed')
                else:
                    target.unlink(); target.symlink_to(self.module / 'sections/Overview.class.php')
                self.assertNotEqual(self.invoke('--uninstalling').returncode, 0)
                target.unlink(missing_ok=True); target.write_bytes(self.stock[self.widgets[1]])
                (self.module / 'sections/Overview.class.php').write_bytes(self.stock['sections/Overview.class.php'])
                (self.module / 'extra.php').unlink(missing_ok=True)

    def test_framework_progress_accepts_only_exact_reviewed_before_or_clean_afterimage(self):
        name = 'amp_conf/htdocs/admin/views/menu_items.php'
        path = self.web / 'admin/views/menu_items.php'; path.parent.mkdir(parents=True)
        before, clean = b'approved menu with SLL insertion', b'approved clean native menu'
        original, _ = TRUST.load(self.store, 'framework')
        original['files'][name] = {'sha256': TRUST.digest(before), 'target': 'admin/views/menu_items.php'}
        original['uninstall']['replace'][name] = TRUST.digest(clean)
        TRUST.store_manifest(self.store, original, (json.dumps(original) + '\n').encode())
        for body in (before, clean):
            path.write_bytes(body)
            TRUST.check(self.store, 'framework', self.web, uninstalling=True)
        path.write_bytes(b'unreviewed menu')
        with self.assertRaises(TRUST.TrustError):
            TRUST.check(self.store, 'framework', self.web, uninstalling=True)

    def test_uninstaller_refresh_can_reach_cleanup_with_sll_tree_already_absent(self):
        (self.module / self.widgets[0]).unlink()
        helpers = self.base / 'helpers'; helpers.mkdir(mode=0o700)
        (helpers / 'sls_module_trust.py').write_bytes(SOURCE.read_bytes())
        # This sentinel must never be invoked for an exact known afterimage.
        sentinel = self.base / 'unexpected-reconciliation'
        (helpers / 'sls_upgrade_trust.py').write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\nraise SystemExit(97)\n')
        shell = self.base / 'uninstall.sh'
        shell.write_text((ROOT / 'tools/uninstall_release.sh').read_text()
            .replace('/var/lib/sls-mass-notify-trust', str(self.store)).replace('/var/www/html', str(self.web)))
        command = '''source "$1"
RECOVERY_SIGNER_DIR="$2"
UNINSTALL_FIXTURE_WORKSPACE="$2/review"
uninstall_recovery_workspace() { mkdir -m700 "$UNINSTALL_FIXTURE_WORKSPACE"; printf '%s\\n' "$UNINSTALL_FIXTURE_WORKSPACE"; }
refresh_uninstall_stock_approvals
'''
        result = subprocess.run(['/bin/bash', '-c', command,
            'fixture', str(shell), str(helpers)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertTrue((self.module / self.widgets[1]).is_file(), 'Verification must not remove a widget')
        self.assertFalse((self.web / 'admin/modules/slsmassnotifyserver').exists())


if __name__ == '__main__':
    unittest.main()
