#!/usr/bin/env python3
"""Exercise installer rollback against private trees and mocked PBX commands."""
import os
import hashlib
import importlib.util
import json
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import tempfile
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()
MODULE = 'slsmassnotifyserver'
HARNESS = r'''
source "$1"
fixture="$2"
scenario="$3"
LOG_FILE="$fixture/commands.log"
CONFIG_FILE="$fixture/config"
CONFIG_SNAPSHOT="$fixture/config.snapshot"
CONFIG_HASH_BEFORE="$(sha256sum "$CONFIG_SNAPSHOT" | cut -d ' ' -f1)"
MODULE_BACKUP_DIR="$fixture/backup"
STAGING_DIR="$fixture/stage"
DOWNLOAD_DIR="$fixture/download"
RECOVERY_DIR="$fixture/recovery"
RECOVERY_TOOL="$fixture/recover.py"
INSTALL_BOOTSTRAP_DIR="$fixture/bootstrap"
UPGRADE_TRUST_DIR="$fixture/approval"
MODULE_ACTIVATED=1
STATIC_MUTATION_STARTED=1
HAD_EXISTING_MODULE=1
MODULE_WAS_ENABLED=1
INSTALL_NOTIFICATION_SIDE_EFFECTS=0
[[ "$scenario" != fresh && "$scenario" != fresh-unrecorded-swap ]] || HAD_EXISTING_MODULE=0
[[ "$scenario" != pre-activation ]] || MODULE_ACTIVATED=0
[[ "$scenario" != fresh-unrecorded-swap ]] || MODULE_ACTIVATED=0
log() { printf '%s\n' "$*" >>"$fixture/messages.log"; }
ensure_data_directory() { return 0; }
safe_config_restore() {
  [[ "$scenario" != config-failure ]] || return 9
  cp -- "$1" "$2"
}
record_install_failure() {
  printf '%s %s\n' "$INSTALL_EXIT_CODE" "$INSTALL_ERROR_CATEGORY" >"$fixture/failure-marker"
}
sls_as_asterisk() { printf "restored-asterisk-config\n" >>"$LOG_FILE"; }
verify_install_idle_history() { printf "retained-phone-history\n" >>"$LOG_FILE"; }
verify_local_api_route() { printf "read-only-api-health\n" >>"$LOG_FILE"; }
refresh_served_php_workers() { printf "refresh-served-php\n" >>"$LOG_FILE"; }
fwconsole() { printf 'FORBIDDEN fwconsole %s\n' "$*" >>"$LOG_FILE"; return 99; }
php() { printf 'FORBIDDEN PHP hook\n' >>"$LOG_FILE"; return 99; }
refresh_module_install() { printf 'FORBIDDEN old install\n' >>"$LOG_FILE"; return 99; }
sign_and_verify_touched_modules() { printf 'FORBIDDEN signer\n' >>"$LOG_FILE"; return 99; }
restore_module_registration() {
  printf 'restore-module-registration\n' >>"$LOG_FILE"
  [[ "$scenario" != registration-failure ]] || return 8
}
if [[ "$scenario" == move-failure ]]; then
  restore_previous_module_tree() { return 19; }
fi
if [[ "$scenario" == repeated-recovery ]]; then
  rollback_module_install || :
  ROLLBACK_FAILED=0
  ROLLBACK_ATTEMPTED=0
fi
trap guard_config_on_exit EXIT
exit 73
'''


class RollbackTests(unittest.TestCase):
    def run_scenario(self, scenario):
        with tempfile.TemporaryDirectory(prefix='sls-rollback-fixture-') as name:
            fixture = Path(name)
            installed = fixture / 'modules' / MODULE
            installed.mkdir(parents=True)
            (installed / 'payload').write_text('failed new release')
            backup = fixture / 'backup'
            backup.mkdir(mode=0o700)
            if not scenario.startswith('fresh'):
                previous = backup / MODULE
                previous.mkdir()
                (previous / 'payload').write_text('original release')
            for directory in ('stage', 'download', 'recovery', 'bootstrap'):
                (fixture / directory).mkdir()
            if scenario == 'fresh-unrecorded-swap':
                # Activation copies the staged source, so the source remains
                # present after rename and before publishing the swap marker.
                (fixture / 'stage' / MODULE).mkdir()
            approval = fixture / 'approval'
            approval.mkdir(mode=0o700)
            prior = None if scenario.startswith('fresh') else {
                'schema': 1, 'module': MODULE, 'version': '0.1.8-beta',
                'source': {'kind': 'publisher-ed25519', 'archive_sha256': 'a' * 64},
                'files': {'payload': {'target': 'admin/modules/' + MODULE + '/payload',
                                      'sha256': hashlib.sha256(b'original release').hexdigest()}}}
            (approval / 'previous-web-approval.json').write_text(json.dumps({MODULE: prior}))
            (approval / 'previous-web-approval.json').chmod(0o600)
            helpers = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
            for name in ('sls_upgrade_trust.py', 'sls_module_trust.py', 'sls_release_trust.py', 'sls_installer_recovery.py'):
                body = (helpers / name).read_text()
                if name == 'sls_upgrade_trust.py':
                    body = body.replace("WEB = Path('/var/www/html')", "WEB = Path(" + repr(str(fixture)) + ")")
                target = fixture / 'bootstrap' / name
                target.write_text(body)
                target.chmod(0o700)
            # Keep the production helper's standard web-root layout in this
            # private filesystem while the shell exercises its actual rollback.
            (fixture / 'admin').mkdir()
            (fixture / 'modules').rename(fixture / 'admin/modules')
            installed = fixture / 'admin/modules' / MODULE
            (fixture/'recovery/module-registration.json').write_text('{"schema":1,"row":null}')
            (fixture/'recover.py').write_text('import pathlib,sys\np=pathlib.Path(sys.argv[2]).parent.parent\nwith (p/"commands.log").open("a") as f: f.write("static-"+sys.argv[3]+"\\n")\nif sys.argv[3]=="restore-maintenance":sys.exit(1)\n')
            (fixture/'config').write_text('changed by failed install')
            snapshot = fixture/'config.snapshot'
            snapshot.write_text('original protected config')
            (fixture/'delivery-ledger').write_text('new receipt committed during install')
            installer = fixture/'installer.sh'
            installer.write_text(SOURCE.replace('/var/www/html/admin/modules', str(fixture/'admin/modules')))
            result = subprocess.run(['bash', '-c', HARNESS, '_', str(installer), str(fixture), scenario],
                capture_output=True, text=True, timeout=20, env={**os.environ,'SLS_MASS_NOTIFY_MODULE':MODULE})
            self.assertEqual(result.returncode,73,result.stdout+result.stderr)
            self.assertEqual((fixture/'failure-marker').read_text().strip(),'73 install_rollback_failed')
            for path in (backup,snapshot,fixture/'stage',fixture/'recovery',fixture/'bootstrap'):
                self.assertTrue(path.exists(),str(path))
            self.assertFalse((fixture/'download').exists())
            log=(fixture/'commands.log').read_text()
            self.assertNotIn('FORBIDDEN',log)
            self.assertIn('static-restore',log)
            self.assertIn('static-verify',log)
            self.assertIn('restore-module-registration',log)
            self.assertEqual((fixture/'delivery-ledger').read_text(),'new receipt committed during install')
            if scenario != 'config-failure':
                self.assertEqual((fixture/'config').read_text(),'original protected config')
            if scenario.startswith('fresh'): self.assertFalse(installed.exists())
            elif scenario not in ('move-failure','pre-activation'):
                self.assertEqual((installed/'payload').read_text(),'original release')
            if scenario not in ('move-failure','pre-activation'):
                self.assertEqual((backup/'failed-module/payload').read_text(),'failed new release')
            self.assertIn('Recovery locations:',(fixture/'messages.log').read_text())
            if scenario == 'repeated-recovery':
                self.assertNotIn('previous module directory could not be restored', (fixture / 'messages.log').read_text())

    def test_static_recovery_never_runs_old_module_hooks(self):
        for scenario in ('normal','fresh','fresh-unrecorded-swap','pre-activation','config-failure','registration-failure','move-failure','repeated-recovery'):
            with self.subTest(scenario=scenario): self.run_scenario(scenario)


class RollbackHistoryHealth(unittest.TestCase):
    def test_rollback_requires_recovered_collector_health_and_an_existing_ledger(self):
        helper = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_install_idle.py'
        spec = importlib.util.spec_from_file_location('rollback_idle_fixture', helper)
        idle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(idle)
        for failure in ('stale', 'missing', 'delayed-startup', 'transient-enterprise-worker', 'persistent-enterprise-worker'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='sll-rollback-health-') as temporary:
                base = Path(temporary)
                data = base / 'data'; data.mkdir(mode=0o750)
                module = base / 'module/module.xml'; module.parent.mkdir(); module.write_bytes(b'<module/>')
                marker = module.with_name('PhoneEventService.php'); marker.write_bytes(b'<?php')
                proc = base / 'proc'; proc.mkdir()
                state = {'schema':1,'collector':{'generation':'b'*32,'boot_id':'fixture-boot','heartbeat_tick':99},
                         'batches':{'a'*32:{'status':'closed','created_at':1,'closed_at':2}}}
                if failure == 'missing':state['batches'] = {}
                ledger = data / 'phone-admission.json'; ledger.write_text(json.dumps(state)); ledger.chmod(0o640)
                check = idle.IdleCheck(data,module=module,proc=proc,spools=(),channels=lambda:'',
                    boot_id='fixture-boot',monotonic=lambda:100,clock=lambda:1000,subsystem_paths=(marker,))
                recovery = base / 'recovery'; recovery.mkdir(mode=0o700)
                baseline = recovery / 'idle-before.json'; baseline.write_text(json.dumps(check.inspect())); baseline.chmod(0o600)
                if failure == 'missing':
                    ledger.unlink()
                elif failure in ('stale', 'delayed-startup'):
                    state['collector']['heartbeat_tick'] = 1
                    ledger.write_text(json.dumps(state))
                else:
                    worker = proc / '42'; worker.mkdir(); (worker / 'cmdline').write_bytes(b'php\0/usr/local/bin/sls_mass_notify/sls_mass_notify_cluster_worker.php\0')
                runner = base / 'idle-runner.py'
                runner.write_text('''import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('actual_idle',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=pathlib.Path(sys.argv[2]);scenario=sys.argv[3];sys.argv=[sys.argv[0],*sys.argv[4:]]
counter=base/'attempts';n=int(counter.read_text())+1 if counter.exists() else 1;counter.write_text(str(n))
if scenario=='delayed-startup' and n==3:
 p=base/'data/phone-admission.json';state=json.loads(p.read_text());state['collector']['heartbeat_tick']=99;p.write_text(json.dumps(state))
if scenario=='transient-enterprise-worker' and n==3:
 (base/'proc/42/cmdline').unlink();(base/'proc/42').rmdir()
original=m.IdleCheck
m.IdleCheck=lambda data:original(data,module=base/'module/module.xml',proc=base/'proc',spools=(),channels=lambda:'',boot_id='fixture-boot',monotonic=lambda:100,clock=lambda:1000,subsystem_paths=(base/'module/PhoneEventService.php',))
try:m.main()
except (m.IdleError,OSError,ValueError):sys.exit(1)
''')
                wrapper = base / 'idle-wrapper'
                wrapper.write_text('#!/bin/bash\nexec ' + shlex.quote(sys.executable) + ' -I ' + shlex.join([str(runner), str(helper), str(base), failure]) + ' "$@"\n')
                wrapper.chmod(0o700)
                # The production shell invokes Python directly. Use a Python
                # launcher to retain the real argument handling and checker.
                launcher = base / 'idle-launcher.py'
                launcher.write_text('import os,sys\nos.execv('+repr(str(wrapper))+','+repr([str(wrapper)])+'+sys.argv[1:])\n')
                script = '''source "$1"
WORKER_LOCK_PID=$$
DATA_DIR="$2/data"; RECOVERY_DIR="$2/recovery"; IDLE_TOOL="$2/idle-launcher.py"
ROLLBACK_ATTEMPTED=1
if [[ "$3" == *enterprise-worker ]]; then ROLLBACK_ATTEMPTED=0; fi
sleep() { :; }
verify_install_idle_history
'''
                result = subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),str(base),failure],
                    capture_output=True,text=True,timeout=15)
                if failure in ('delayed-startup', 'transient-enterprise-worker'):
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertGreaterEqual(int((base/'attempts').read_text()),3)
                else:
                    self.assertNotEqual(result.returncode,0,'Rollback accepted an unavailable collector or ledger: '+failure)

@unittest.skipUnless(os.geteuid() == 0, 'Root is required to reproduce root-owned umask027 directories with an unprivileged PHP reader.')
class ApiDirectoryPermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sls-api-permissions-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.reader = pwd.getpwnam('nobody')
        self.web = self.root / 'web'; self.web.mkdir(mode=0o711)
        self.web.chmod(0o711)
        self.module = self.root / 'modules' / MODULE
        self.source = self.module / 'api'
        for name in ('sipnotify', 'sls-mass-notify'):
            source = self.source / name
            (source / 'nested').mkdir(parents=True)
            (source / 'index.php').write_text("<?php require __DIR__ . '/nested/body.php';")
            (source / 'nested/body.php').write_text("<?php echo 'api-readable';")
            (source / '.htaccess').write_text('Options -Indexes\n')
        text = (ROOT / 'slsmassnotifyserver/Slsmassnotifyserver.class.php').read_text()
        methods = []
        for name in ('readManagedTextFile', 'unlinkNamedFileIfIdentity', 'writeManagedTextFile',
                     'copyRuntimeFile', 'copyRuntimeDirectory'):
            start = text.index('\tprivate function ' + name + '(')
            end = text.index('\n\tprivate function ', start + 1)
            method = text[start:end].replace('private function', 'public function', 1)
            method = method.replace("'/var/www/html/'", repr(str(self.web) + '/'))
            methods.append(method)
        self.php = self.root / 'copy.php'
        self.php.write_text('<?php\numask(0027);\nclass CopyFixture {\nconst PLUGIN_DATA_DIR = ' + repr(str(self.root)) + ';\n' + '\n'.join(methods) +
            '\n}\n(new CopyFixture())->copyRuntimeDirectory($argv[1], $argv[2], 0644, true, $argv[3] === "public" ? 0755 : null);\n')
        self.installer = self.root / 'installer.sh'
        self.installer.write_text(SOURCE.replace('/var/www/html/admin/modules', str(self.root / 'modules'))
                                       .replace('/var/www/html/api', str(self.web / 'api'))
                                       .replace('/var/www/html/mass-notify', str(self.web / 'mass-notify')))

    def copy(self, name, public=False):
        target = self.web / 'api' / name
        result = subprocess.run(['php', str(self.php), str(self.source/name), str(target), 'public' if public else 'legacy'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return target

    def read_as_web_user(self, target):
        def drop_privileges():
            os.setgroups([])
            os.setgid(self.reader.pw_gid)
            os.setuid(self.reader.pw_uid)
        return subprocess.run(['php', str(target/'index.php')], capture_output=True, text=True,
                              timeout=10, preexec_fn=drop_privileges)

    def prepare_legacy_copy(self):
        # The real FreePBX API parent already exists and is traversable. The
        # legacy copier newly creates only its module-owned children as0750.
        (self.web/'api').mkdir(mode=0o755)
        (self.web/'api').chmod(0o755)
        targets = [self.copy(name) for name in ('sipnotify', 'sls-mass-notify')]
        for target in targets:
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o750)
            self.assertEqual(target.stat().st_uid, 0)
            self.assertNotEqual(self.read_as_web_user(target).returncode, 0)
        return targets

    def repair(self):
        return subprocess.run(['bash', '-c', 'source "$1"; repair_restored_api_directory_access', '_', str(self.installer)],
                              capture_output=True, text=True, timeout=10,
                              env={**os.environ, 'SLS_MASS_NOTIFY_MODULE': MODULE})

    def prepare_portal_copy(self):
        source = self.module / 'portal'
        source.mkdir()
        (source / 'index.php').write_text("<?php echo 'portal-readable';")
        (source / '.htaccess').write_text('Options -Indexes\n')
        target = self.web / 'mass-notify'
        result = subprocess.run(['php', str(self.php), str(source), str(target), 'legacy'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o750)
        self.assertNotEqual(self.read_as_web_user(target).returncode, 0)
        return target

    def test_new_copy_under_restrictive_umask_is_immediately_readable(self):
        for name in ('sipnotify', 'sls-mass-notify'):
            target = self.copy(name, public=True)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((target/'nested').stat().st_mode), 0o755)
            result = self.read_as_web_user(target)
            self.assertEqual((result.returncode, result.stdout), (0, 'api-readable'), result.stderr)
        self.assertEqual(stat.S_IMODE(self.web.stat().st_mode), 0o711)

    def test_explicit_public_copy_repairs_existing_owned_directories(self):
        targets = self.prepare_legacy_copy()
        for target in targets:
            self.copy(target.name, public=True)
            self.assertEqual(self.read_as_web_user(target).stdout, 'api-readable')

    def test_real_legacy_rollback_repair_preserves_private_data_and_shared_parents(self):
        targets = self.prepare_legacy_copy()
        protected = self.root/'protected.config'
        protected.write_text('private fixture config'); protected.chmod(0o640)
        before = (protected.read_bytes(), protected.stat().st_mode, self.web.stat().st_mode)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        for target in targets:
            read = self.read_as_web_user(target)
            self.assertEqual((read.returncode, read.stdout), (0, 'api-readable'), read.stderr)
        self.assertEqual(before, (protected.read_bytes(), protected.stat().st_mode, self.web.stat().st_mode))

    def test_source_mismatch_fails_before_changing_either_api_tree(self):
        targets = self.prepare_legacy_copy()
        (targets[1]/'index.php').write_text('unexpected modified PHP')
        self.assertNotEqual(self.repair().returncode, 0)
        for target in targets:
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o750)

    def test_rollback_repairs_portal_and_apis_when_restored_release_has_portal(self):
        targets = self.prepare_legacy_copy()
        portal = self.prepare_portal_copy()
        protected = self.root / 'protected.config'
        protected.write_text('private fixture config'); protected.chmod(0o640)
        before = (protected.read_bytes(), protected.stat().st_mode, self.web.stat().st_mode)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        for target, expected in [(target, 'api-readable') for target in targets] + [(portal, 'portal-readable')]:
            read = self.read_as_web_user(target)
            self.assertEqual((read.returncode, read.stdout), (0, expected), read.stderr)
        self.assertEqual(before, (protected.read_bytes(), protected.stat().st_mode, self.web.stat().st_mode))

    def test_portal_mismatch_rejects_rollback_before_any_public_permissions_change(self):
        targets = self.prepare_legacy_copy()
        portal = self.prepare_portal_copy()
        (portal / 'index.php').write_text('unexpected portal PHP')
        self.assertNotEqual(self.repair().returncode, 0)
        for target in targets + [portal]:
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o750)

    def test_symlink_target_cannot_change_directory_outside_owned_api(self):
        targets = self.prepare_legacy_copy()
        outside = self.root/'outside'; outside.mkdir(mode=0o700)
        shutil.rmtree(targets[1]/'nested')
        (targets[1]/'nested').symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.repair().returncode, 0)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(targets[0].stat().st_mode), 0o750)

    def test_hardlinked_or_extra_file_rejects_unverified_tree(self):
        targets = self.prepare_legacy_copy()
        os.link(targets[1]/'index.php', self.root/'hardlink')
        self.assertNotEqual(self.repair().returncode, 0)
        (self.root/'hardlink').unlink()
        (targets[1]/'extra.php').write_text('unpackaged file')
        self.assertNotEqual(self.repair().returncode, 0)
        self.assertEqual(stat.S_IMODE(targets[0].stat().st_mode), 0o750)


if __name__ == '__main__':
    unittest.main()
