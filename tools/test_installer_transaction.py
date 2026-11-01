#!/usr/bin/env python3
"""Run the actual installer transaction with private trees and inert PBX phases."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'tools/install_release.sh').read_text()
HARNESS=r'''
source "$1"
fixture="$2"; scenario="$3"
DATA_DIR="$fixture/data"; CONFIG_FILE="$DATA_DIR/mass-notifications.config"
SETTINGS_LOCK="$DATA_DIR/mass-notifications.config.lock"
INSTALL_TRANSACTION_ROOT="$fixture/journal"; TGZ="$fixture/package.tgz"
LOG_FILE="$fixture/install.log"; INSTALL_NOTIFICATION_SIDE_EFFECTS=0
trace() { printf '%s\n' "$*" >>"$fixture/trace"; }
mktemp() {
 case "$*" in
  '-d /tmp/sls-mass-notify-bootstrap.XXXXXX') command mktemp -d "$fixture/bootstrap.XXXXXX" ;;
  *'.sls-mass-notify-recovery.XXXXXX') command mktemp -d "$fixture/web/admin/modules/.sls-mass-notify-recovery.XXXXXX" ;;
  '/tmp/slsmassnotifyserver-config.XXXXXX') command mktemp "$fixture/config-backup.XXXXXX" ;;
  '/tmp/slsmassnotifyserver-pending.XXXXXX') command mktemp "$fixture/pending-backup.XXXXXX" ;;
  *) command mktemp "$@" ;;
 esac
}
ensure_installer_log_prerequisites() { :; }
preflight_hardware_requirements() { :; }
require_freepbx() { :; }
acquire_update_coordination() { trace update-lock; }
acquire_maintenance_coordination() { trace maintenance-lock; }
install_dependencies() { :; }
preflight_platform() { :; }
preflight_python() { :; }
detect_served_php_profiles() { SERVED_PHP_PROFILES='8.2:apache2'; }
verify_served_php_configuration() { :; }
verify_php_security_versions_before_mutation() { trace php-security-floor; [ "$scenario" != php-rejected ] || return 38; }
verify_freepbx_web_response() { [ "$scenario" != web-rejected ] || return 41; }
bootstrap_missing_dashboard() { trace stock-dashboard-bootstrap; }
preflight_profile_identity() { :; }
ensure_freepbx_prerequisites() { :; }
initialize_configuration_keyring() { trace config-keyring-init; }
prepare_module_ami_intent() { trace protected-ami-intent; }
download_tgz() {
 DOWNLOAD_DIR="$fixture/download"; mkdir "$DOWNLOAD_DIR"
 printf 'fixture package' >"$TGZ"
 printf '{}' >"$DOWNLOAD_DIR/release-manifest.json"
 printf 'fixture signature' >"$DOWNLOAD_DIR/release-manifest.sig"
}
verify_tgz() { trace signed-input; }
ensure_data_directory() { :; }
validate_preserved_config_prerequisites() { :; }
validate_staged_central_config() { :; }
verify_staged_hardware_requirements() { :; }
stage_module_directory() {
 STAGING_DIR="${FIXTURE_STAGING:-$fixture/stage}"; mkdir -m700 "$STAGING_DIR"; mkdir "$STAGING_DIR/$MODULE"
 printf candidate >"$STAGING_DIR/$MODULE/module.xml"
 mkdir -p "$STAGING_DIR/$MODULE/bin/sls_mass_notify"
 cp "$FIXTURE_HELPERS"/sls_{module_trust,release_trust,privileged_install,installer_recovery,install_transaction,install_idle,install_guard,audio_state,config_crypto,upgrade_trust,legacy_permissions}.py "$STAGING_DIR/$MODULE/bin/sls_mass_notify/"
 cp "$FIXTURE_HELPERS/freepbx-mirror-signing.pub" "$STAGING_DIR/$MODULE/bin/sls_mass_notify/"
 /usr/bin/python3 -I - "$STAGING_DIR/$MODULE/bin/sls_mass_notify/sls_upgrade_trust.py" "$fixture/web" <<'PYFIXTUREWEB'
from pathlib import Path
import sys
p=Path(sys.argv[1]);p.write_text(p.read_text().replace("WEB = Path('/var/www/html')",'WEB = Path('+repr(sys.argv[2])+')'))
PYFIXTUREWEB
 HAD_EXISTING_MODULE=1; MODULE_WAS_ENABLED=1
}
prepare_authenticated_installer() {
 trace approval-preflight
 if [ "$scenario" = approval-rejected ]; then return 31; fi
 UPGRADE_TRUST_DIR="$fixture/approval"; mkdir -m700 "$UPGRADE_TRUST_DIR"
 cp "$fixture/previous-web-approval.json" "$UPGRADE_TRUST_DIR/previous-web-approval.json"
 RECOVERY_TOOL="$fixture/recovery.py"; IDLE_TOOL="$fixture/idle.py"
}
commit_authenticated_installer() {
 RECOVERY_TOOL="$fixture/recovery.py"; IDLE_TOOL="$fixture/idle.py"
 RECOVERY_DIR="$(command mktemp -d "$INSTALL_TRANSACTION_DIR/sls-mass-notify-recovery.XXXXXX")"
 chmod 0700 "$RECOVERY_DIR"
 printf '{"schema":1,"ok":true,"phone_history":{},"closed_phone_batches":0}' >"$RECOVERY_DIR/idle-before.json"
 printf '{"schema":3}' >"$RECOVERY_DIR/module-registration.json"
 chmod 0600 "$RECOVERY_DIR/idle-before.json" "$RECOVERY_DIR/module-registration.json"
 seal_install_recovery_inputs
 trace approved-snapshot; STATIC_MUTATION_STARTED=1
 persist_install_transaction mutating
}
protect_freepbx_chown_permissions() { trace chown-protected; [ "$scenario" != chown-failed ] || return 35; }
repair_authenticated_legacy_permissions() { trace legacy-permissions-repaired; [ "$scenario" != legacy-permissions-failed ] || return 36; }
preflight_authenticated_prerequisites() { trace approved-prerequisites; }
restore_previous_phone_collector() { trace previous-collector-healthy; [ "$scenario" != collector-failed ] || return 37; }
configure_system_timezone() { trace timezone; }
protected_install_phase() {
 trace "protected-$*"
 if [ "$scenario" = prepare-failed ] && [ "$1" = prepare ]; then return 32; fi
}
install_module_with_autoenable() {
 trace module-install
 [ "${SLS_MASS_NOTIFY_DEFER_SIGNING:-}" = 1 ] || return 99
 if [ "$scenario" = install-failed ]; then return 33; fi
}
sync_module_version() { trace module-db; }
ensure_runtime_installed() { trace runtime-parity; }
secure_central_config() { :; }
fwconsole() { trace "asterisk-fwconsole-$*"; [ "$1" != reload ] || [ "${SLS_MASS_NOTIFY_PRESERVE_PENDING:-}" = 1 ]; }
sls_as_asterisk() { trace "asterisk-fixed-command"; }
verify_runtime_shell_syntax() { :; }
verify_announcement_worker_health() { :; }
verify_piper_voices() { :; }
verify_phone_collector() { trace collector-ready; [ "$scenario" != startup-collector-failed ] || return 39; }
verify_served_php_runtime() { trace served-php; }
verify_install() { trace verification; if [ "$scenario" = pending-drift ]; then printf modified >"$DATA_DIR/mass-notifications.pending.config"; fi; [[ "$scenario" != final-failed* ]] || return 34; }
verify_confirmed_system_timezone() { :; }
clear_install_failure() { trace success; }
restore_module_registration() { trace db-restored; }
verify_local_api_route() { trace recovered-route; }
record_install_failure() { trace "failure-$INSTALL_EXIT_CODE-$INSTALL_ERROR_CATEGORY"; }
# The real journal, stage recording, worker locks, settings snapshots, module
# swap, rollback ordering and final cleanup remain in use. PBX/provider phases
# and release authentication are inert; no fixture grants trust to live files.
main
'''

@unittest.skipUnless(os.geteuid()==0,'requires root for protected staging/worker lock fixtures')
class TransactionTests(unittest.TestCase):
 def make_private_backup(self,root):
  installer=root/'installer.sh';installer.write_text(SOURCE.replace('/var/www/html',str(root/'web')))
  return subprocess.run(['bash','-c','source "$1"; create_module_recovery_directory','fixture',str(installer)],capture_output=True,text=True,timeout=5)
 def test_module_backup_uses_private_same_mount_parent_and_reuses_it_safely(self):
  with tempfile.TemporaryDirectory(prefix='sls-private-module-backups-') as name:
   root=Path(name);public=root/'web/admin/modules';public.mkdir(parents=True)
   results=[self.make_private_backup(root) for _ in range(2)]
   for result in results:self.assertEqual(result.returncode,0,result.stderr)
   paths=[Path(result.stdout.strip()) for result in results]
   self.assertNotEqual(paths[0],paths[1])
   for path in [paths[0].parent,*paths]:
    self.assertEqual((path.stat().st_uid,path.stat().st_gid,path.stat().st_mode&0o7777),(0,0,0o700))
    self.assertEqual(path.stat().st_dev,public.stat().st_dev)
   self.assertEqual(paths[0].parent,public/'.sls-mass-notify-recovery')
 def test_module_backup_rejects_unsafe_existing_anchor_without_adopting_it(self):
  import pwd
  for kind in ('symlink','runtime-owned','public','file','fifo','mount-alias'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='sls-private-module-backups-') as name:
    root=Path(name);public=root/'web/admin/modules';public.mkdir(parents=True)
    anchor=public/'.sls-mass-notify-recovery';victim=root/'untouched';victim.mkdir(mode=0o700)
    (victim/'file').write_bytes(b'preserve');(victim/'file').chmod(0o600)
    mounted=False
    if kind=='symlink':anchor.symlink_to(victim,target_is_directory=True)
    elif kind=='file':anchor.write_bytes(b'preserve');anchor.chmod(0o600)
    elif kind=='fifo':os.mkfifo(anchor,0o600)
    else:
     anchor.mkdir(mode=0o700)
     if kind=='runtime-owned':account=pwd.getpwnam('asterisk');os.chown(anchor,account.pw_uid,account.pw_gid)
     elif kind=='public':anchor.chmod(0o775)
     elif kind=='mount-alias':subprocess.run(['/usr/bin/mount','--bind',str(victim),str(anchor)],check=True,capture_output=True);mounted=True
    before=anchor.lstat()
    try:
     result=self.make_private_backup(root);self.assertNotEqual(result.returncode,0)
     after=anchor.lstat();self.assertEqual((before.st_ino,before.st_uid,before.st_gid,before.st_mode),(after.st_ino,after.st_uid,after.st_gid,after.st_mode))
     self.assertEqual((victim/'file').read_bytes(),b'preserve');self.assertEqual(list(victim.iterdir()),[victim/'file'])
    finally:
     if mounted:subprocess.run(['/usr/bin/umount',str(anchor)],check=True,capture_output=True)
 def test_private_module_backup_handles_a_native_group_inheriting_parent(self):
  import pwd
  with tempfile.TemporaryDirectory(prefix='sls-private-module-backups-') as name:
   root=Path(name);public=root/'web/admin/modules';public.mkdir(parents=True)
   account=pwd.getpwnam('asterisk');os.chown(public,account.pw_uid,account.pw_gid);public.chmod(0o2775)
   result=self.make_private_backup(root);self.assertEqual(result.returncode,0,result.stderr)
   path=Path(result.stdout.strip())
   for item in (path,path.parent):self.assertEqual((item.stat().st_uid,item.stat().st_gid,item.stat().st_mode&0o7777),(0,0,0o700))
 def test_empty_interrupted_root_anchor_is_repaired_without_replacing_its_inode(self):
  import pwd
  with tempfile.TemporaryDirectory(prefix='sls-private-module-backups-') as name:
   root=Path(name);public=root/'web/admin/modules';public.mkdir(parents=True)
   anchor=public/'.sls-mass-notify-recovery';anchor.mkdir(mode=0o700)
   os.chown(anchor,0,pwd.getpwnam('asterisk').pw_gid);anchor.chmod(0o2700);before=anchor.stat().st_ino
   result=self.make_private_backup(root);self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(anchor.stat().st_ino,before)
   self.assertEqual((anchor.stat().st_uid,anchor.stat().st_gid,anchor.stat().st_mode&0o7777),(0,0,0o700))
 def run_case(self,scenario,expected,cross_mount=False):
  with tempfile.TemporaryDirectory(prefix='sls-installer-transaction-') as name:
   root=Path(name); data=root/'data';data.mkdir();config=data/'mass-notifications.config';config.write_text('{"preserve":"exact bytes"}\n')
   module=root/'web/admin/modules/slsmassnotifyserver';module.mkdir(parents=True);(module/'module.xml').write_text('original')
   prior={'slsmassnotifyserver':{'schema':1,'module':'slsmassnotifyserver','version':'0.1.8-beta',
    'source':{'kind':'publisher-ed25519','archive_sha256':'a'*64},
    'files':{'module.xml':{'target':'admin/modules/slsmassnotifyserver/module.xml',
     'sha256':hashlib.sha256(b'original').hexdigest()}}},'dashboard':None,'framework':None}
   approval=root/'previous-web-approval.json';approval.write_text(json.dumps(prior));approval.chmod(0o600)
   (data/'delivery-ledger').write_text('current receipt')
   pending=data/'mass-notifications.pending.config';pending.write_text('{"staged":"preserve exact bytes"}\n')
   installer=root/'installer.sh';installer.write_text(SOURCE.replace('/var/www/html',str(root/'web')))
   if scenario=='unknown-prepared-stage':
    installer.write_text(installer.read_text().replace('set_install_stage "FreePBX ownership protection"', 'set_install_stage "unrecognized fixture stage"'))
   elif scenario=='unknown-mutating-stage':
    installer.write_text(installer.read_text().replace('set_install_stage "module activation"', 'set_install_stage "unrecognized fixture stage"'))
   (root/'recovery.py').write_text('import pathlib,sys\np=pathlib.Path(__file__).parent\nwith (p/"trace").open("a") as f:f.write("static-"+sys.argv[-1]+"\\n")\nif sys.argv[-1]=="restore-maintenance" and '+repr(scenario)+'!="final-failed-rollback-ok":sys.exit(1)\n')
   (root/'idle.py').write_text('import json\nprint(json.dumps({"ok":True}))\n')
   environment={**os.environ,'FIXTURE_HELPERS':str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify')}
   if cross_mount:
    separate=Path(tempfile.mkdtemp(prefix='sls-stage-parent-',dir='/run'))
    self.addCleanup(__import__('shutil').rmtree,separate,True)
    self.assertNotEqual(separate.stat().st_dev,module.stat().st_dev,'cross-mount regression requires the isolated test namespaces')
    environment['FIXTURE_STAGING']=str(separate/'stage')
   result=subprocess.run(['bash','-c',HARNESS,'fixture',str(installer),str(root),scenario],capture_output=True,text=True,timeout=20,env=environment)
   self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
   self.assertEqual(config.read_text(),'{"preserve":"exact bytes"}\n')
   self.assertEqual((data/'delivery-ledger').read_text(),'current receipt')
   self.assertEqual(pending.read_text(),'{"staged":"preserve exact bytes"}\n')
   trace=(root/'trace').read_text().splitlines()
   journals=list((root/'journal').glob('transaction-*/transaction.json'))
   if scenario in ('approval-rejected','php-rejected','web-rejected'):
    self.assertEqual(journals,[])
   else:
    self.assertEqual(len(journals),1)
    journal=json.loads(journals[0].read_text())
    expected_phase={'success':'committed','unknown-prepared-stage':'abandoned','final-failed-rollback-ok':'rolled_back',
                    'chown-failed':'abandoned','legacy-permissions-failed':'abandoned','collector-failed':'abandoned'}.get(scenario,'recovery_failed')
    self.assertEqual(journal['phase'],expected_phase)
    self.assertEqual(journals[0].stat().st_mode & 0o777,0o600)
    expected_stage={'unknown-prepared-stage':'publisher and stock approval','unknown-mutating-stage':'protected runtime preparation','prepare-failed':'protected runtime preparation','install-failed':'module activation',
                    'chown-failed':'FreePBX ownership protection','legacy-permissions-failed':'legacy configuration and runtime permissions','collector-failed':'previous phone collector recovery','startup-collector-failed':'runtime integration'}.get(scenario,'post-install verification')
    self.assertEqual(journal['stage'],expected_stage)
    self.assertEqual(bool(list(journals[0].parent.glob('config.snapshot'))),expected_phase=='recovery_failed')
   self.assertNotIn('asterisk-fwconsole-chown',trace)
   if scenario=='success':
    self.assertEqual((module/'module.xml').read_text(),'candidate')
    self.assertLess(trace.index('protected-activate --apply'),trace.index('asterisk-fwconsole-reload'))
    self.assertLess(trace.index('asterisk-fwconsole-reload'),trace.index('protected-verify'))
    self.assertLess(trace.index('asterisk-fwconsole-reload'),trace.index('collector-ready'))
    self.assertLess(trace.index('collector-ready'),trace.index('protected-verify'))
    self.assertLess(trace.index('protected-ami-intent'),trace.index('module-install'))
    self.assertEqual(trace[-1],'success')
    phases=['php-security-floor','stock-dashboard-bootstrap','approval-preflight','chown-protected','legacy-permissions-repaired','approved-prerequisites','previous-collector-healthy','approved-snapshot','protected-prepare --apply']
    self.assertEqual([trace.index(item) for item in phases],sorted(trace.index(item) for item in phases))
    self.assertEqual(list(journals[0].parent.glob('sls-mass-notify-recovery.*')),[])
   else:
    self.assertEqual((module/'module.xml').read_text(),'original')
    if scenario in ('approval-rejected','php-rejected','web-rejected'):
     self.assertFalse(any(x.startswith('static-') for x in trace))
     failure={'php-rejected':'failure-38-php_security_preflight_failed','web-rejected':'failure-41-freepbx_web_preflight_failed'}.get(scenario,'failure-31-install_command_failed')
     self.assertIn(failure,trace)
     self.assertNotIn('chown-protected',trace)
     self.assertNotIn('legacy-permissions-repaired',trace)
     if scenario in ('php-rejected','web-rejected'):
      self.assertNotIn('stock-dashboard-bootstrap',trace)
      self.assertNotIn('approval-preflight',trace)
    elif scenario=='unknown-prepared-stage':
     self.assertFalse(any(x.startswith('static-') for x in trace))
     self.assertIn('failure-2-installer_stage_recording_failed',trace)
     self.assertNotIn('chown-protected',trace)
    elif scenario in ('chown-failed','legacy-permissions-failed','collector-failed'):
     self.assertFalse(any(x.startswith('static-') for x in trace))
     category={'chown-failed':'install_command_failed','legacy-permissions-failed':'legacy_permission_recovery_failed','collector-failed':'previous_collector_recovery_failed'}[scenario]
     self.assertIn('failure-'+str(expected)+'-'+category,trace)
    else:
     self.assertIn('static-restore',trace);self.assertIn('static-restore-services',trace);self.assertIn('db-restored',trace)
     if scenario=='final-failed-rollback-ok':
      self.assertEqual(list(journals[0].parent.glob('sls-mass-notify-recovery.*')),[])
      self.assertIn('failure-34-install_command_failed',trace)
     else:
      self.assertTrue((Path(journal['settings']['RECOVERY_DIR'])/'idle-before.json').exists())
      self.assertIn('failure-'+str(expected)+'-install_rollback_failed',trace)
   # The EXIT guard always releases worker slots, including every failure path.
   import fcntl
   if scenario not in ('approval-rejected','php-rejected','web-rejected','unknown-prepared-stage','chown-failed','legacy-permissions-failed','collector-failed'):
    with (data/'schedule-runner.lock').open('r+') as handle:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
   else:
    self.assertFalse((data/'schedule-runner.lock').exists())
 def test_successful_candidate_transaction(self):self.run_case('success',0)
 def test_separate_scratch_mount_supports_activation_and_rollback(self):
  self.run_case('success',0,True)
  self.run_case('final-failed',34,True)
 def test_prerequisite_rejection_does_not_restore_or_disable_old_automation(self):self.run_case('approval-rejected',31)
 def test_security_floor_rejection_precedes_stock_bootstrap_and_trust_mutation(self):self.run_case('php-rejected',38)
 def test_broken_freepbx_web_response_precedes_stock_bootstrap_and_trust_mutation(self):self.run_case('web-rejected',41)
 def test_failure_stages_preserve_old_module_config_and_operational_records(self):
  for scenario,code in [('prepare-failed',32),('install-failed',33),('startup-collector-failed',39),('final-failed',34),('pending-drift',1)]:
   with self.subTest(scenario=scenario):self.run_case(scenario,code)
 def test_verified_rollback_is_recorded_before_evidence_cleanup(self):self.run_case('final-failed-rollback-ok',34)
 def test_unknown_stage_preserves_the_last_valid_stage_for_finalization(self):
  self.run_case('unknown-prepared-stage',2)
  self.run_case('unknown-mutating-stage',2)
 def test_prepared_permission_and_collector_failures_record_completion(self):
  for scenario,code in [('chown-failed',35),('legacy-permissions-failed',36),('collector-failed',37)]:
   with self.subTest(scenario=scenario):self.run_case(scenario,code)

if __name__=='__main__':unittest.main()
