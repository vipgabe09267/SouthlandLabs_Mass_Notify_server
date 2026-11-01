#!/usr/bin/env python3
"""Private descriptor-removal qualification; never invoke a real uninstall."""
import errno
import importlib.util
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('private_uninstall_fixture', Path(__file__).with_name('test_uninstaller_transaction.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ContainedRemoval(unittest.TestCase):
    setUp = fixture.OfflineUninstaller.setUp
    shell = fixture.OfflineUninstaller.shell

    def invoke(self, path, action='remove'):
        return self.shell('remove_managed_path "$SLS_TEST_PATH" "$SLS_TEST_ACTION"\n',
                          env={'SLS_TEST_PATH': str(path), 'SLS_TEST_ACTION': action})

    def bind_mount(self, source, target):
        subprocess.run(['/usr/bin/mount','--bind',str(source),str(target)],check=True,capture_output=True,text=True)
        self.addCleanup(subprocess.run,['/usr/bin/umount',str(target)],check=False,capture_output=True,text=True)

    def program(self, path, action='remove'):
        body = self.script.read_text().split("<<'PYMANAGEDREMOVE'\n", 1)[1].split('\nPYMANAGEDREMOVE', 1)[0]
        with mock.patch.object(sys, 'argv', ['fixture', str(path), str(self.data), action]):
            try:
                exec(compile(body, 'actual-private-removal-helper', 'exec'), {'__name__': 'fixture'})
            except SystemExit as error:
                if error.code not in (0, None):
                    raise RuntimeError(str(error)) from error

    def api(self, owner=None):
        owner = self.account.pw_uid if owner is None else owner
        self.web.mkdir(mode=0o775, exist_ok=True)
        os.chown(self.web, self.account.pw_uid, self.account.pw_gid)
        parent = self.web / 'api'; parent.mkdir(mode=0o775, exist_ok=True)
        os.chown(parent, self.account.pw_uid, self.account.pw_gid)
        path = parent / 'sls-mass-notify'; path.mkdir(mode=0o755)
        os.chown(path, owner, self.account.pw_gid)
        return path

    def outside(self):
        outside = self.base / 'root-only'; outside.mkdir(mode=0o700)
        victim = outside / 'sls-mass-notify'; victim.mkdir(mode=0o700)
        sentinel = victim / 'config-keys.json'; sentinel.write_text('retained root private sentinel')
        sentinel.chmod(0o600)
        return outside, sentinel

    def replace_as_asterisk(self, path, target):
        def drop():
            os.setgroups([self.account.pw_gid]); os.setgid(self.account.pw_gid); os.setuid(self.account.pw_uid)
        result = subprocess.run(['/usr/bin/python3', '-I', '-c',
            'import os,sys;os.rename(sys.argv[1],sys.argv[1]+".saved");os.symlink(sys.argv[2],sys.argv[1]);print(os.geteuid())',
            str(path), str(target)], preexec_fn=drop, capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(result.stdout.strip(), str(self.account.pw_uid))

    def test_root_and_asterisk_trees_remove_only_the_anchored_tree(self):
        for owner in (0, self.account.pw_uid):
            with self.subTest(owner=owner):
                path = self.api(owner)
                (path / 'ordinary').write_text('private managed bytes')
                nested = path / 'nested'; nested.mkdir(); (nested / 'deep').write_text('managed')
                outside = self.base / ('outside-' + str(owner)); outside.mkdir(mode=0o700)
                sentinel = outside / 'preserved'; sentinel.write_text('preserved')
                (path / 'do-not-follow').symlink_to(outside, target_is_directory=True)
                before = (path / 'ordinary').read_bytes()
                self.assertEqual(self.invoke(path, 'check').returncode, 0)
                self.assertEqual((path / 'ordinary').read_bytes(), before)
                self.assertEqual(self.invoke(path).returncode, 0)
                self.assertFalse(path.exists()); self.assertEqual(sentinel.read_text(), 'preserved')

    def test_leaf_link_is_unlinked_without_following_its_target(self):
        path = self.api(); path.rmdir()
        outside, sentinel = self.outside(); path.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.invoke(path, 'check').returncode, 0)
        self.assertTrue(path.is_symlink())
        self.assertEqual(self.invoke(path).returncode, 0)
        self.assertFalse(path.is_symlink()); self.assertTrue(sentinel.exists())

    def test_preexisting_asterisk_replaced_parent_is_refused(self):
        path = self.api(); (path / 'managed').write_text('managed')
        outside, sentinel = self.outside()
        self.replace_as_asterisk(path.parent, outside)
        for action in ('check', 'remove'):
            self.assertNotEqual(self.invoke(path, action).returncode, 0)
            self.assertEqual(sentinel.read_text(), 'retained root private sentinel')
            self.assertEqual((Path(str(path.parent) + '.saved') / path.name / 'managed').read_text(), 'managed')

    def test_named_root_changed_after_validation_cannot_redirect_removal(self):
        path = self.api(); (path / 'managed').write_text('managed')
        outside, sentinel = self.outside(); real = os.listdir; changed=[]
        def replace(name):
            if isinstance(name,int) and not changed:
                self.replace_as_asterisk(path,outside);changed.append(True)
            return real(name)
        with mock.patch.object(os,'listdir',side_effect=replace):
            with self.assertRaises((OSError,RuntimeError)): self.program(path)
        self.assertTrue(path.is_symlink()); self.assertTrue(sentinel.exists())
        self.assertEqual(changed,[True])
        self.assertTrue(Path(str(path) + '.saved').is_dir())

    def test_parent_changed_after_validation_stays_in_the_held_directory(self):
        path = self.api(); (path / 'managed').write_text('managed')
        outside, sentinel = self.outside(); real = os.listdir; changed=[]
        def replace(name):
            if isinstance(name,int) and not changed:
                self.replace_as_asterisk(path.parent,outside);changed.append(True)
            return real(name)
        with mock.patch.object(os,'listdir',side_effect=replace): self.program(path)
        self.assertEqual(changed,[True])
        self.assertTrue(path.parent.is_symlink()); self.assertTrue(sentinel.exists())
        self.assertFalse((Path(str(path.parent) + '.saved') / path.name).exists())

    def test_internal_directory_changed_during_descent_does_not_escape(self):
        path = self.api(); nested = path / 'nested'; nested.mkdir()
        os.chown(nested, self.account.pw_uid, self.account.pw_gid)
        (nested / 'managed').write_text('managed')
        outside, sentinel = self.outside(); real_open = os.open; changed = []
        def replace(name, flags, *args, **kwargs):
            # The helper's read-only validation opens with O_DIRECTORY;
            # CPython's safe rmtree opens the child with O_RDONLY and compares
            # fstat against its preceding no-follow directory identity.
            if name == 'nested' and flags & os.O_DIRECTORY and kwargs.get('dir_fd') is not None and not changed:
                self.replace_as_asterisk(nested, outside); changed.append(True)
            return real_open(name, flags, *args, **kwargs)
        with mock.patch.object(os, 'open', side_effect=replace):
            with self.assertRaises(OSError):
                self.program(path)
        self.assertEqual(changed, [True]); self.assertTrue(sentinel.exists())
        self.assertEqual((Path(str(nested) + '.saved') / 'managed').read_text(), 'managed')

    def test_unknown_owner_group_and_special_entry_are_not_adopted(self):
        path = self.api(); foreign = pwd.getpwnam('nobody'); entry = path / 'unknown'; entry.write_text('preserved')
        os.chown(entry, foreign.pw_uid, foreign.pw_gid)
        before = entry.stat()
        for action in ('check', 'remove'):
            self.assertNotEqual(self.invoke(path, action).returncode, 0)
        self.assertEqual((entry.stat().st_uid, entry.stat().st_gid), (before.st_uid, before.st_gid))
        entry.unlink(); fifo = path / 'special'; os.mkfifo(fifo, 0o600)
        self.assertNotEqual(self.invoke(path).returncode, 0); self.assertTrue(fifo.exists())
        fifo.unlink(); os.chown(path.parent, 0, foreign.pw_gid)
        self.assertNotEqual(self.invoke(path).returncode, 0); self.assertTrue(path.exists())

    def test_hardlinked_entries_are_preserved_before_any_tree_mutation(self):
        path = self.api(); normal = path / 'managed'; normal.write_text('managed')
        peer = self.base / 'root-peer'; peer.write_text('retained'); os.link(peer, path / 'linked')
        self.assertNotEqual(self.invoke(path).returncode, 0)
        self.assertEqual(normal.read_text(), 'managed'); self.assertEqual(peer.read_text(), 'retained')
        self.assertEqual(peer.stat().st_nlink, 2)

    def test_nested_directory_bind_mount_is_rejected_during_preflight(self):
        path=self.api();normal=path/'managed';normal.write_text('managed')
        outside,sentinel=self.outside();target=path/'mounted';target.mkdir()
        before=(sentinel.read_bytes(),sentinel.stat().st_uid,sentinel.stat().st_mode)
        self.bind_mount(outside,target)
        for action in ('check','remove'):
            self.assertNotEqual(self.invoke(path,action).returncode,0)
            self.assertEqual((sentinel.read_bytes(),sentinel.stat().st_uid,sentinel.stat().st_mode),before)
            self.assertEqual(normal.read_text(),'managed')

    def test_bind_mounted_root_and_regular_file_are_rejected(self):
        path=self.api();outside,sentinel=self.outside();self.bind_mount(outside,path)
        self.assertNotEqual(self.invoke(path,'check').returncode,0)
        self.assertEqual(sentinel.read_text(),'retained root private sentinel')
        subprocess.run(['/usr/bin/umount',str(path)],check=True,capture_output=True,text=True)
        path.rmdir();path.mkdir();source=self.base/'outside-file';source.write_text('external file')
        target=path/'mounted-file';target.write_text('placeholder');before=(source.read_bytes(),source.stat().st_mode,source.stat().st_uid)
        self.bind_mount(source,target)
        for action in ('check','remove'):
            self.assertNotEqual(self.invoke(path,action).returncode,0)
            self.assertEqual((source.read_bytes(),source.stat().st_mode,source.stat().st_uid),before)

    def test_failure_propagates_and_retry_can_remove_the_same_valid_tree(self):
        path = self.api(); (path / 'managed').write_text('managed')
        real=os.unlink
        def fail(name,*args,**kwargs):
            if name=='managed' and kwargs.get('dir_fd') is not None: raise OSError(errno.EIO,'fixture storage failure')
            return real(name,*args,**kwargs)
        with mock.patch.object(os,'unlink',side_effect=fail):
            with self.assertRaises(OSError): self.program(path)
        self.assertEqual((path / 'managed').read_text(), 'managed')
        self.assertEqual(self.invoke(path).returncode, 0); self.assertFalse(path.exists())

    def test_depth_bound_fails_before_any_tree_mutation(self):
        path = self.api(); normal = path / 'managed'; normal.write_text('managed'); current = path
        for _ in range(130): current = current / 'd'; current.mkdir()
        self.assertNotEqual(self.invoke(path).returncode, 0)
        self.assertEqual(normal.read_text(), 'managed'); self.assertTrue(current.exists())

    def test_missing_and_unsupported_paths_and_action_controls(self):
        path = self.web / 'api/sls-mass-notify'
        self.assertEqual(self.invoke(path).returncode, 0)
        self.assertNotEqual(self.invoke(self.web / 'api/unrelated').returncode, 0)
        self.assertNotEqual(self.invoke(path, 'erase-anything').returncode, 0)
        self.assertNotEqual(self.invoke(str(self.web / 'api') + '/../api/sls-mass-notify').returncode, 0)

    def test_preflight_checks_are_before_service_and_module_teardown(self):
        path = self.api(); (path / 'managed').write_text('managed')
        outside, sentinel = self.outside(); self.replace_as_asterisk(path.parent, outside)
        trace = self.base / 'preflight.trace'
        result = self.shell('''eval "$(declare -f remove_managed_path | sed '1s/remove_managed_path/remove_managed_path_real/')"
remove_managed_path() {
  printf '%s|%s\\n' "$1" "$2" >>"$SLS_TEST_TRACE"
  test "$2" = check || return 95
  if [[ "$1" = "$SLS_TEST_WEB/"* ]]; then remove_managed_path_real "$@"; fi
}
preflight_managed_removals
printf 'UNSAFE SERVICE CHANGE\\n'
''', env={'SLS_TEST_TRACE':str(trace),'SLS_TEST_WEB':str(self.web)})
        self.assertNotEqual(result.returncode, 0); self.assertNotIn('UNSAFE SERVICE CHANGE', result.stdout)
        self.assertTrue(sentinel.exists())
        self.assertTrue(all(row.endswith('|check') for row in trace.read_text().splitlines()))
        body = self.script.read_text().split('main() {', 1)[1]
        for later in ('remove_phone_collector_service','remove_freepbx_manager_users','remove_module_registration'):
            self.assertLess(body.index('preflight_managed_removals'), body.index(later))

    def test_empty_legacy_alias_directories_and_nonempty_preservation(self):
        parent = self.data / 'piper/venv/bin'; parent.mkdir(parents=True)
        retained = parent / 'unrelated'; retained.write_text('preserved')
        self.assertEqual(self.invoke(parent).returncode, 0); self.assertTrue(retained.exists())
        retained.unlink(); self.assertEqual(self.invoke(parent).returncode, 0); self.assertFalse(parent.exists())
        self.assertEqual(self.invoke(parent.parent).returncode, 0); self.assertFalse(parent.parent.exists())

    def test_module_removal_refuses_replaced_modules_ancestor(self):
        modules = self.web / 'admin/modules'; modules.mkdir(parents=True)
        for directory in (self.web, self.web / 'admin', modules):
            os.chown(directory, self.account.pw_uid, self.account.pw_gid)
        outside = self.base / 'module-outside'; outside.mkdir(mode=0o700)
        victim = outside / 'slsmassnotifyserver'; victim.mkdir(); sentinel = victim / 'preserved'; sentinel.write_text('preserved')
        self.replace_as_asterisk(modules, outside)
        result = self.shell('inspect_module_registry() { MODULE_REGISTRY_PRESENT=0; }\nremove_module_registration\n')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(sentinel.read_text(), 'preserved')

    def test_managed_sound_links_keep_custom_paths_and_never_follow_targets(self):
        sounds = self.base / 'sounds'; sounds.mkdir()
        body = self.script.read_text().replace('/var/lib/asterisk/sounds', str(sounds))
        self.script.write_text(body)
        link = sounds / 'SLS_Mass_Notifications_Plugin'
        link.symlink_to(str(self.data / 'sounds'), target_is_directory=True)
        self.assertEqual(self.invoke(link, 'check').returncode, 0); self.assertTrue(link.is_symlink())
        self.assertEqual(self.invoke(link).returncode, 0); self.assertFalse(link.is_symlink())
        outside, sentinel = self.outside(); link.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.invoke(link).returncode, 0); self.assertTrue(link.is_symlink()); self.assertTrue(sentinel.exists())
        link.unlink(); link.mkdir(); custom = link / 'custom'; custom.write_text('custom recording')
        self.assertEqual(self.invoke(link).returncode, 0); self.assertEqual(custom.read_text(), 'custom recording')

    def test_preflight_covers_all_fixed_removals_and_purge_is_explicit(self):
        expected = {
            str(self.web / 'admin/modules/slsmassnotifyserver'), '/etc/asterisk/slsmassnotify',
            str(self.web / 'admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php'),
            str(self.web / 'admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php'),
            '/usr/local/bin/sls_mass_notify', str(self.installed / 'slsconsole'),
            '/usr/local/bin/nwsalerts_ensure_menu_patch.sh', str(self.installed / 'sign_sls_mass_notify_local_sig.sh'),
            '/etc/freepbx.secure/slsmassnotifyserver.sig', '/var/lib/asterisk/bin/sls_mass_notify',
            '/var/lib/asterisk/bin/sls_mass_notify_test.sh', str(self.web / 'api/sls-mass-notify'),
            str(self.web / 'api/sipnotify'), str(self.web / 'mass-notify'), str(self.web / 'sls_mass_notify'),
            '/var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin',
            '/var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin',
            str(self.data / 'piper/venv/bin/piper'), str(self.data / 'piper/venv/bin'), str(self.data / 'piper/venv'),
            '/var/tmp/nws_last_clear.ts',
        }
        purge_only = {str(self.data), '/var/log/sls_mass_notify.log', '/var/log/sls_mass_notify_events.jsonl',
                      '/var/log/sls_mass_notify_push.log'}
        for purge in ('0', '1'):
            result = self.shell('PURGE_CONFIG='+purge+'\nremove_managed_path() { test "$2" = check || return 95; printf "%s\\n" "$1"; }\npreflight_managed_removals\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = result.stdout.splitlines()
            self.assertEqual(len(actual), len(set(actual)), 'Preflight duplicates a fixed removal path')
            self.assertEqual(set(actual), expected | (purge_only if purge == '1' else set()))

    def test_supported_asterisk_owned_etc_directory_is_accepted(self):
        # /etc/asterisk is service-owned mode 0775 on qualified FreePBX. This
        # path is hidden by the unchanged runner's private tmpfs mount.
        directory = Path('/etc/asterisk'); before = directory.stat()
        target = directory / 'slsmassnotify'
        self.assertFalse(target.exists())
        try:
            os.chown(directory, self.account.pw_uid, self.account.pw_gid); directory.chmod(0o775)
            target.write_text('managed alias'); os.chown(target, self.account.pw_uid, self.account.pw_gid)
            self.assertEqual(self.invoke(target, 'check').returncode, 0)
            self.assertEqual(target.read_text(), 'managed alias')
            self.assertEqual(self.invoke(target).returncode, 0); self.assertFalse(target.exists())
        finally:
            if target.exists(): target.unlink()
            os.chown(directory, before.st_uid, before.st_gid); directory.chmod(stat.S_IMODE(before.st_mode))

    def test_data_directory_cannot_redefine_the_fixed_removal_allowlist(self):
        path = self.api(); marker = path / 'managed'; marker.write_text('managed')
        result = self.shell('DATA_DIR="$SLS_TEST_BAD_DATA"\nremove_managed_path "$SLS_TEST_PATH"\n',
            env={'SLS_TEST_BAD_DATA':str(self.base / 'other-state'), 'SLS_TEST_PATH':str(path)})
        self.assertNotEqual(result.returncode, 0); self.assertEqual(marker.read_text(), 'managed')


if __name__ == '__main__':
    unittest.main()
