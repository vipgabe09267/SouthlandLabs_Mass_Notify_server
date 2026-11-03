#!/usr/bin/env python3
"""Exercise native module registration results without a PBX or database."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'tools/install_release.sh'


class NativeRegistration(unittest.TestCase):
    def run_install(self, result='true', *, enabled=1, version='0.1.9-beta', status='enabled', operation='install', rows=1):
        # The real installer PHP program runs against only its native boundary:
        # the registry and native install return. No hook or PBX bootstrap runs.
        with tempfile.TemporaryDirectory(prefix='sls-native-registration-') as folder:
            root = Path(folder)
            fixture = root / 'native.php'
            fixture.write_text('''<?php
define('MODULE_STATUS_ENABLED',2); define('MODULE_STATUS_DISABLED',1);
define('MODULE_STATUS_NOTINSTALLED',0); define('MODULE_STATUS_NEEDUPGRADE',3);
class NativeDatabase {
 public function prepare($sql) {
  if (preg_match('/UPDATE|INSERT|DELETE/i',$sql)) {throw new RuntimeException('Synthetic registry writes are forbidden');}
  return new class {
   public function execute($args) {return true;}
   public function fetchAll($mode=null) {return array_fill(0,(int)getenv('FIXTURE_ROWS'),['version'=>getenv('FIXTURE_VERSION'),'enabled'=>getenv('FIXTURE_ENABLED')]);}
   public function fetchColumn() {return getenv('FIXTURE_VERSION');}
  };
 }
}
class NativeModules {public function loadAllFunctionsInc() {}}
class FreePBX {
 public $Modules;
 public function __construct() {$this->Modules=new NativeModules;}
 public static function Create() {return new self;}
 public static function Database() {return new NativeDatabase;}
 public static function Modules() {return new NativeModules;}
}
class module_functions {
 private $didEnable=false;
 public static function create() {return new self;}
 public function getinfo($name) {return [$name=>['status'=>$this->didEnable?MODULE_STATUS_ENABLED:constant('MODULE_STATUS_'.strtoupper(getenv('FIXTURE_STATUS'))),'version'=>'0.1.9-beta']];}
 public function install($name,$force=false,$ignorechecks=true) {
  if ($force || $ignorechecks) {throw new RuntimeException('Native dependency/conflict checks were bypassed');}
  file_put_contents(getenv('FIXTURE_CALLS'),"install\\n",FILE_APPEND);
  return match(getenv('FIXTURE_RESULT')) {'true'=>true,'false'=>false,'empty'=>[],'dependency'=>['Dependency backup requires >=17.0.1'],'hook'=>['Failed to run installation scripts'],default=>['native refusal']};
 }
 public function enable($name,$force=false,$ignorechecks=true) {
  file_put_contents(getenv('FIXTURE_CALLS'),"enable\\n",FILE_APPEND); $this->didEnable=true; return true;
 }
}
''')
            harness = r'''source "$1"
LOG_FILE="$2/log"; fixture_php="$2/native.php"
php() {
 local program="$2"
 /usr/bin/php -r '$program=str_replace("require \"/etc/freepbx.conf\";", "", $argv[1]); require getenv("FIXTURE_BOOTSTRAP"); eval($program);' "$program"
}
run_without_install_maintenance_lock() { "$@"; }
fwconsole() { printf '| slsmassnotifyserver | 0.1.9-beta | Nicht installiert |\n'; return 0; }
case "$FIXTURE_OPERATION" in
 install) install_module_with_autoenable ;;
 sync) sync_module_version ;;
 state) module_registry_state slsmassnotifyserver ;;
 stage)
  CONFIG_FILE="$2/retained.config"; INSTALL_TEMP_ROOT="$2"; TGZ="$2/archive"
  tar() { mkdir "$STAGING_DIR/slsmassnotifyserver"; printf '<module/>' >"$STAGING_DIR/slsmassnotifyserver/module.xml"; }
  lint_staged_module_php() { :; }
  stage_module_directory
  printf 'HAD=%s ENABLED=%s\n' "$HAD_EXISTING_MODULE" "$MODULE_WAS_ENABLED"
  ;;
esac
'''
            env = {**os.environ, 'FIXTURE_RESULT': result, 'FIXTURE_ENABLED': str(enabled),
                   'FIXTURE_VERSION': version, 'FIXTURE_STATUS': status,
                   'FIXTURE_OPERATION': operation, 'FIXTURE_ROWS': str(rows),
                   'FIXTURE_BOOTSTRAP': str(fixture),
                   'FIXTURE_CALLS': str(root / 'calls')}
            proc = subprocess.run(['/bin/bash', '-c', harness, 'fixture', str(INSTALLER), str(root)],
                                  env=env, text=True, capture_output=True, timeout=10)
            if (root / 'log').exists():
                proc.stdout += (root / 'log').read_text()
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            return proc, calls

    def test_native_refusal_is_not_hidden_by_zero_cli_exit_or_same_version(self):
        for result in ('false', 'empty', 'errors'):
            with self.subTest(result=result):
                proc, calls = self.run_install(result)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(calls, 'install\n')

    def test_native_dependency_and_hook_refusals_are_diagnosable_without_retries(self):
        for result, message in [('dependency', 'Dependency backup requires >=17.0.1'),
                                ('hook', 'Failed to run installation scripts')]:
            with self.subTest(result=result):
                proc, calls = self.run_install(result)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(calls, 'install\n')
                self.assertIn(message, proc.stdout + proc.stderr)

    def test_success_requires_native_result_and_enabled_matching_registration(self):
        proc, calls = self.run_install()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(calls, 'install\n')
        for kwargs in ({'enabled': 0}, {'version': '0.1.8-beta'}):
            with self.subTest(**kwargs):
                proc, calls = self.run_install(**kwargs)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(calls, 'install\n')

    def test_disabled_module_is_enabled_once_before_the_native_install(self):
        proc, calls = self.run_install(status='disabled')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(calls, 'enable\ninstall\n')

    def test_sync_cannot_write_a_version_to_conceal_a_refused_native_install(self):
        proc, calls = self.run_install(operation='sync')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(calls, '')
        proc, calls = self.run_install(operation='sync', version='0.1.8-beta')
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(calls, '')

    def test_registry_state_uses_native_boolean_and_version_not_translated_table(self):
        for kwargs, expected in [({}, 'enabled\t0.1.9-beta\n'), ({'enabled': 0}, 'disabled\t0.1.9-beta\n'),
                                 ({'rows': 0}, 'absent\n')]:
            with self.subTest(**kwargs):
                proc, calls = self.run_install(operation='state', **kwargs)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(proc.stdout, expected)
                self.assertEqual(calls, '')
        for kwargs in ({'enabled': 2}, {'rows': 2}, {'version': 'invalid\nversion'}):
            with self.subTest(**kwargs):
                proc, calls = self.run_install(operation='state', **kwargs)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(calls, '')

    def test_locally_available_unregistered_tree_is_fresh_even_when_cli_lists_it(self):
        proc, calls = self.run_install(operation='stage', rows=0)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('HAD=0 ENABLED=0', proc.stdout)
        self.assertEqual(calls, '')


class NativePrerequisites(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory(prefix='sls-native-prerequisites-') as folder:
            root = Path(folder)
            script = r'''source "$1"
fixture="$2"; mode="$3"; LOG_FILE="$fixture/log"; INSTALL_TEMP_ROOT="$fixture"
trace() { printf '%s\n' "$*" >>"$fixture/trace"; }
module_registry_state() {
 local name="$1"
 if [ "$mode" = read-failed ]; then return 17; fi
 if [ "$name" = backup ] && [ "$mode" = missing ] && [ ! -f "$fixture/installed" ]; then printf 'absent\n'
 elif [ "$name" = backup ] && [ "$mode" = disabled ] && [ ! -f "$fixture/installed" ]; then printf 'disabled\t17.0.13\n'
 else printf 'enabled\t17.0.13\n'; fi
}
fwconsole() {
 if [ "$*" = 'ma list' ]; then
  for name in framework dashboard backup recordings; do printf '| %s | 17.0.13 | Aktiviert |\n' "$name"; done
  return 0
 fi
 if [[ "$*" == *' download backup' ]]; then trace 'download backup'; return 0; fi
 trace "unexpected CLI mutation: $*"; return 9
}
install_native_module() { trace "native-install $1"; touch "$fixture/installed"; }
enable_native_module() { trace "native-enable $1"; touch "$fixture/installed"; }
ensure_freepbx_prerequisites
'''
            proc = subprocess.run(['/bin/bash', '-c', script, 'fixture', str(INSTALLER), str(root), mode],
                                  text=True, capture_output=True, timeout=10)
            trace = (root / 'trace').read_text() if (root / 'trace').exists() else ''
            return proc, trace

    def test_translated_cli_status_cannot_reenable_already_enabled_prerequisites(self):
        proc, trace = self.exercise('enabled')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(trace, '')

    def test_only_an_absent_prerequisite_is_downloaded_and_natively_installed(self):
        proc, trace = self.exercise('missing')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(trace, 'download backup\nnative-install backup\n')

    def test_registered_disabled_prerequisite_is_enabled_without_reinstall(self):
        proc, trace = self.exercise('disabled')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(trace, 'native-enable backup\n')

    def test_unreadable_registry_never_authorizes_a_prerequisite_change(self):
        proc, trace = self.exercise('read-failed')
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(trace, '')


class MissingDashboard(unittest.TestCase):
    def exercise_dashboard(self, version):
        with tempfile.TemporaryDirectory(prefix='sls-dashboard-native-') as folder:
            root = Path(folder)
            source = INSTALLER.read_text()
            body = source[source.index('bootstrap_missing_dashboard() {'):source.index('\ndetect_served_php_profiles()')]
            body = body.replace('/var/www/html/admin/modules/dashboard', str(root/'dashboard'))
            script = r'''set -euo pipefail
fixture="$1"; INSTALL_TEMP_ROOT="$fixture"; INSTALL_BOOTSTRAP_DIR="$fixture/helpers"
SLS_MASS_NOTIFY_BOOTSTRAP_DASHBOARD_VERSION="$2"
trace() { printf '%s\n' "$*" >>"$fixture/trace"; }
log() { :; }
run_logged() { mkdir "$fixture/dashboard"; trace authenticated-stage; }
fwconsole() { trace "unexpected CLI mutation: $*"; return 9; }
install_native_module() { trace "native-install $1"; }
module_enabled() { [ "$1" = dashboard ]; }
''' + body + '\nbootstrap_missing_dashboard\n'
            proc = subprocess.run(['/bin/bash', '-c', script, 'fixture', str(root),version], text=True, capture_output=True, timeout=10)
            trace=(root/'trace').read_text() if (root/'trace').exists() else ''
            return proc,trace

    def test_authenticated_absent_dashboard_uses_exactly_one_native_registration(self):
        proc,trace=self.exercise_dashboard('17.0.5')
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        self.assertEqual(trace,'authenticated-stage\nnative-install dashboard\n')

    def test_dashboard_below_security_floor_is_refused_before_staging_or_hooks(self):
        for version in ('17.0.4','17.0.4.99','unknown','17.0.5-beta'):
            with self.subTest(version=version):
                proc,trace=self.exercise_dashboard(version)
                self.assertNotEqual(proc.returncode,0,proc.stdout+proc.stderr)
                self.assertEqual(trace,'')


if __name__ == '__main__':
    unittest.main()
