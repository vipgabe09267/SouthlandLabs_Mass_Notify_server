#!/usr/bin/env python3
"""Real PHP MFA writes and recovery against disposable encrypted configuration."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
HELPERS=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
PHP=r'''<?php
declare(strict_types=1);
namespace FreePBX\modules { function time(): int { return (int)getenv('FIXTURE_MFA_NOW'); } }
namespace {
require getenv('FIXTURE_MODULE').'/Operators.php';
use SLS\MassNotify\{OperatorAuth as Auth,OperatorAccess as Access};
use FreePBX\modules\SlsConfigCrypto as Crypto;
define('MFA_FIXTURE',getenv('FIXTURE_DATA'));
class ActualMfaWriter {
 use \FreePBX\modules\SlsOperators;
 const SETTINGS_JSON=MFA_FIXTURE.'/mass-notifications.config';
 const PENDING_SETTINGS_JSON=MFA_FIXTURE.'/mass-notifications.pending.config';
 private function acquireSettingsLock(...$unused){
  $handle=fopen(MFA_FIXTURE.'/mass-notifications.config.lock','c+b');
  if(($signal=getenv('FIXTURE_MFA_LOCK_SIGNAL'))!==false&&$signal!==''){file_put_contents($signal,'waiting');}
  if(!is_resource($handle)||!flock($handle,LOCK_EX)){throw new \RuntimeException('fixture lock failed');}
  \SLS\MassNotify\ImmediateSettings::recoverFiles(self::SETTINGS_JSON,self::PENDING_SETTINGS_JSON);return $handle;
 }
 private function releaseSettingsLock($handle):void{fclose($handle);}
 private function loadSettingsFile($path):array{return Crypto::readFile($path);}
 private function writeSettingsFileUnlocked($path,$settings,$backup):void{
  if($path===self::PENDING_SETTINGS_JSON&&getenv('FIXTURE_PARTIAL_COMMIT')==='before'){exit(77);}
  $temporary=$path.'.fixture-write';
  if(file_put_contents($temporary,Crypto::encode($settings))===false){throw new \RuntimeException('fixture write failed');}
  chmod($temporary,0640);if(!rename($temporary,$path)){throw new \RuntimeException('fixture rename failed');}
  if($path===self::PENDING_SETTINGS_JSON&&getenv('FIXTURE_PARTIAL_COMMIT')==='after'){exit(78);}
 }
}
$operation=$argv[1];$module=new ActualMfaWriter;
if($operation==='seed'){
 $settings=['desktop_auth_key'=>base64_encode(str_repeat('k',32)),'unrelated_active'=>['enabled'=>true,'number'=>7],
  'provider_fixture'=>['url'=>'https://provider.example.invalid','secret'=>'synthetic-provider-secret'],
  'immediate_config_revisions'=>['operator_access'=>7,'unrelated_active'=>3]];
 $id='api_'.str_repeat('a',24);$secret=Auth::base32('12345678901234567890');
 $auth=['password_hash'=>Auth::dummyHash(),'version'=>str_repeat('b',64),'force_password_change'=>false,
  'totp_secret_enc'=>Auth::seal($secret,$id,$settings),'totp_last_counter'=>intdiv((int)getenv('FIXTURE_MFA_NOW'),30)-5,
  'recovery_hashes'=>[hash('sha256','11111111-22222222-33333333-44444444')]];
 $account=['id'=>$id,'username'=>'mfa-fixture','name'=>'Fixture','source'=>'portal','role'=>'administrator',
  'enabled'=>true,'expires_at'=>0,'site_ids'=>[],'group_ids'=>[],'auth'=>$auth];
 $account['identity']=Auth::identity($account);
 $other=$account;$other['id']='api_'.str_repeat('e',24);$other['username']='other-mfa-fixture';
 $other['auth']['totp_secret_enc']=Auth::seal($secret,$other['id'],$settings);$other['identity']=Auth::identity($other);
 $settings['operator_access']=Access::normalize(['enabled'=>false,'portal_enabled'=>true,'accounts'=>[$account,$other]]);
 $pending=$settings;$pending['pending_only']=['preserve'=>'staged'];$pending['immediate_config_revisions']['operator_access']=11;
 foreach([[ActualMfaWriter::SETTINGS_JSON,$settings],[ActualMfaWriter::PENDING_SETTINGS_JSON,$pending]] as [$path,$value]){
  file_put_contents($path,Crypto::encode($value));chmod($path,0640);
 }
 echo json_encode(['seeded'=>true],JSON_THROW_ON_ERROR);
}elseif($operation==='state'){
 echo json_encode(['active'=>Crypto::readFile(ActualMfaWriter::SETTINGS_JSON),
  'pending'=>is_file(ActualMfaWriter::PENDING_SETTINGS_JSON)?Crypto::readFile(ActualMfaWriter::PENDING_SETTINGS_JSON):null],JSON_THROW_ON_ERROR);
}elseif($operation==='different-secret'){
 $settings=Crypto::readFile(ActualMfaWriter::SETTINGS_JSON);$account=$settings['operator_access']['accounts'][0];
 echo json_encode(['sealed'=>Auth::seal(Auth::base32('01234567890123456789'),$account['id'],$settings)],JSON_THROW_ON_ERROR);
}else{
 $settings=Crypto::readFile(ActualMfaWriter::SETTINGS_JSON);$account=$settings['operator_access']['accounts'][$operation==='login-other'?1:0];
 $code=$argv[2]??Auth::code(Auth::open($account['auth']['totp_secret_enc'],$account['id'],$settings),intdiv((int)getenv('FIXTURE_MFA_NOW'),30));
 try{$result=$module->operatorAuthUpdate($account['id'],Auth::identity($account),'totp',$code);
  echo json_encode(['accepted'=>true,'code'=>$code,'counter'=>$result['account']['auth']['totp_last_counter']],JSON_THROW_ON_ERROR);
 }catch(\DomainException $error){echo json_encode(['accepted'=>false,'message'=>$error->getMessage()],JSON_THROW_ON_ERROR);}
}
}
'''
GUARD=r'''
source "$1"
fixture="$2"; CONFIG_FILE="$fixture/data/mass-notifications.config"
CONFIG_SNAPSHOT="$fixture/transaction-aaaaaaaaaaaaaaaaaaaaaaaa/config.snapshot"
CONFIG_HASH_BEFORE="$(safe_config_hash "$CONFIG_SNAPSHOT")"
PENDING_CONFIG_PATH="$fixture/data/mass-notifications.pending.config"
PENDING_CONFIG_SNAPSHOT="$fixture/transaction-aaaaaaaaaaaaaaaaaaaaaaaa/pending.snapshot"
PENDING_CONFIG_HASH="$(safe_config_hash "$PENDING_CONFIG_SNAPSHOT")";PENDING_CONFIG_STATE=present
RECOVERY_DIR="$fixture/transaction-aaaaaaaaaaaaaaaaaaaaaaaa/recovery"
TRANSACTION_TOOL="$fixture/bootstrap/sls_install_transaction.py";RECOVERY_REQUEST_MODE=1
verify_recovery_configuration
'''
EXIT_GUARD=r'''
LOG_FILE="$fixture/log";INSTALL_NOTIFICATION_SIDE_EFFECTS=0
# PBX static restoration is inert here; the real shell configuration restore,
# target selection, conflict guard and final postconditions remain executable.
log() { printf '%s\n' "$*" >>"$fixture/log"; }
ensure_data_directory() { :; }
persist_install_transaction() { printf '%s\n' "$1" >>"$fixture/phases"; }
rollback_module_install() { printf 'static-restored\n' >>"$fixture/trace"; ROLLBACK_ATTEMPTED=1; ROLLBACK_VERIFIED=1; }
rollback_failure() { printf '%s\n' "$*" >>"$fixture/rollback-failed"; ROLLBACK_FAILED=1; }
restore_freepbx_chown_permissions() { :; }
record_install_failure() { :; }
clear_install_failure() { :; }
release_worker_coordination() { :; }
INSTALL_TRANSACTION_DIR="";STATIC_MUTATION_STARTED=1
set +e
false
guard_config_on_exit
'''
class MfaRecoveryIntegration(unittest.TestCase):
 def setUp(self):
  if os.environ.get('SLS_TEST_NAMESPACE')!='entered':raise RuntimeError('Use tools/run_isolated_tests.sh; disposable PBX state is required.')
  for label,kind in [('MOUNT','mnt'),('NET','net'),('PID','pid'),('IPC','ipc')]:
   parent=os.environ.get('SLS_TEST_PARENT_'+label+'_NS')
   if not parent or parent==os.readlink('/proc/self/ns/'+kind):
    raise RuntimeError('The official wrapper must enter a fresh '+label+' namespace before any crypto import.')
  self.temporary=tempfile.TemporaryDirectory(prefix='sls-mfa-recovery-');self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
  self.data=self.root/'data';self.data.mkdir(mode=0o700)
  self.transaction=self.root/('transaction-'+'a'*24);self.transaction.mkdir(mode=0o700);(self.transaction/'recovery').mkdir(mode=0o700)
  bootstrap=self.root/'bootstrap';bootstrap.mkdir(mode=0o700)
  for name in ['sls_install_transaction.py','sls_config_crypto.py']:
   shutil.copyfile(HELPERS/name,bootstrap/name);(bootstrap/name).chmod(0o600)
  self.php=self.root/'actual-mfa.php';self.php.write_text(PHP);self.now=1900000000;self.assertTrue(self.run_php('seed')['seeded'])
  spec=importlib.util.spec_from_file_location('mfa_fixture_crypto',HELPERS/'sls_config_crypto.py')
  self.crypto=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.crypto)
  for name,target in [('mass-notifications.config','config.snapshot'),('mass-notifications.pending.config','pending.snapshot')]:
   shutil.copyfile(self.data/name,self.transaction/target);(self.transaction/target).chmod(0o600)
  self.original_snapshots={name:(self.transaction/name).read_bytes() for name in ['config.snapshot','pending.snapshot']}
 def php_process(self,operation,*arguments,extra_env=None):
  return subprocess.run(['php',str(self.php),operation,*arguments],env={**os.environ,'FIXTURE_MFA_NOW':str(self.now),'FIXTURE_MODULE':str(ROOT/'slsmassnotifyserver'),'FIXTURE_DATA':str(self.data),**(extra_env or {})},capture_output=True,text=True,timeout=15)
 def run_php(self,operation,*arguments):
  result=self.php_process(operation,*arguments)
  self.assertEqual(result.returncode,0,result.stderr);return json.loads(result.stdout)
 @contextlib.contextmanager
 def keeper(self):
  process=subprocess.Popen([sys.executable,'-I',str(HELPERS/'sls_install_guard.py'),'--data',str(self.data),'--settings','--timeout','5','hold'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   self.assertTrue(select.select([process.stdout],[],[],8)[0],'keeper did not become ready');self.assertEqual(process.stdout.readline().strip(),'ready');yield
  finally:
   if process.poll() is None:process.stdin.write('release\n');process.stdin.flush()
   stdout,stderr=process.communicate(timeout=8);self.assertEqual(process.returncode,0,stderr)
 def test_actual_totp_login_is_accepted_by_recovery(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted']);state=self.run_php('state')
  self.assertEqual(state['active']['immediate_config_revisions']['operator_access'],12)
  with self.keeper():
   result=subprocess.run(['bash','-c',GUARD,'fixture',str(ROOT/'tools/install_release.sh'),str(self.root)],capture_output=True,text=True,timeout=15)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(self.run_php('state'),state)
  self.assertFalse(self.run_php('login',consumed['code'])['accepted'])

 def run_guard(self,action='prepare',already_locked=False):
  # Build every input through the actual installer shell function, keeping the
  # namespace's real permanent settings mutex held by its real worker keeper.
  setup=GUARD.rsplit('verify_recovery_configuration',1)[0]
  commands={
   'prepare':'verify_recovery_configuration\n',
   'exit':EXIT_GUARD,
   'crash-after-targets':'verify_recovery_configuration || exit $?\nkill -KILL "$$"\n',
   'crash-between-restores':'verify_recovery_configuration || exit $?\nsafe_config_restore "$CONFIG_RECOVERY_SNAPSHOT" "$CONFIG_FILE" || exit $?\nkill -KILL "$$"\n',
  }
  def execute():return subprocess.run(['bash','-c',setup+commands[action],'fixture',str(ROOT/'tools/install_release.sh'),str(self.root)],capture_output=True,text=True,timeout=20)
  if already_locked:return execute()
  with self.keeper():return execute()

 def encrypted_bytes(self):
  return tuple((self.data/name).read_bytes() for name in ['mass-notifications.config','mass-notifications.pending.config'])

 def settings(self):
  return {key:self.crypto.read_config(self.data/name) for key,name in [('active','mass-notifications.config'),('pending','mass-notifications.pending.config')]}

 def write_settings(self,state):
  for key,name in [('active','mass-notifications.config'),('pending','mass-notifications.pending.config')]:
   path=self.data/name;path.write_bytes(self.crypto.encode_config(state[key]));path.chmod(0o640)

 def assert_originals_preserved(self):
  for name,body in self.original_snapshots.items():self.assertEqual((self.transaction/name).read_bytes(),body)

 def assert_exit_preserves_mfa(self,consumed):
  expected=self.settings();result=self.run_guard('exit')
  self.assertEqual(result.returncode,0,result.stderr+'\n'+(self.root/'log').read_text())
  self.assertFalse((self.root/'rollback-failed').exists())
  self.assertEqual(self.settings(),expected)
  self.assertEqual(self.settings()['pending']['pending_only'],{'preserve':'staged'})
  self.assertFalse(self.run_php('login',consumed['code'])['accepted'])
  self.now+=30
  following=self.run_php('login');self.assertTrue(following['accepted'])
  self.assertEqual(following['counter'],consumed['counter']+1)
  state=self.settings();self.assertEqual(state['active']['immediate_config_revisions']['operator_access'],13)
  self.assertEqual(state['active']['operator_access'],state['pending']['operator_access'])

 def test_actual_exit_guard_keeps_consumed_code_and_next_code_works(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted'])
  self.assert_exit_preserves_mfa(consumed)

 def test_process_kill_after_durable_targets_then_normal_retry(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted'])
  result=self.run_guard('crash-after-targets');self.assertEqual(result.returncode,-9,result.stderr)
  self.assertTrue((self.transaction/'recovery/configuration-mfa-recovery.json').is_file())
  self.assert_originals_preserved();self.assert_exit_preserves_mfa(consumed)

 def test_process_kill_between_active_and_pending_restore_then_retry(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted'])
  result=self.run_guard('crash-between-restores');self.assertEqual(result.returncode,-9,result.stderr)
  self.assert_originals_preserved();self.assert_exit_preserves_mfa(consumed)

 def test_retry_after_another_real_mfa_login_preserves_highest_counter(self):
  self.retry_with_another_login('crash-after-targets')

 def test_retry_after_partial_restore_and_another_login_preserves_highest(self):
  self.retry_with_another_login('crash-between-restores')

 def retry_with_another_login(self,boundary):
  first=self.run_php('login');self.assertTrue(first['accepted'])
  result=self.run_guard(boundary);self.assertEqual(result.returncode,-9,result.stderr)
  self.now+=30;second=self.run_php('login');self.assertTrue(second['accepted'])
  expected=self.settings();self.assertEqual(expected['active']['immediate_config_revisions']['operator_access'],13)
  result=self.run_guard('exit');self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(self.settings(),expected)
  self.assertFalse(self.run_php('login',first['code'])['accepted'])
  self.assertFalse(self.run_php('login',second['code'])['accepted'])

 def test_replay_floor_is_bound_to_the_existing_account(self):
  before=self.settings();consumed=self.run_php('login-other');self.assertTrue(consumed['accepted'])
  expected=self.settings()
  self.assertEqual(expected['active']['operator_access']['accounts'][0],before['active']['operator_access']['accounts'][0])
  self.assertEqual(self.run_guard('exit').returncode,0)
  self.assertEqual(self.settings(),expected)
  self.assertFalse(self.run_php('login-other',consumed['code'])['accepted'])
  # The independent fixture account has its own replay floor, even though these
  # synthetic credentials deliberately share the RFC test secret.
  self.assertTrue(self.run_php('login',consumed['code'])['accepted'])

 def test_real_login_waits_for_recovery_keeper_and_consumes_after_release(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted']);self.now+=30
  signal=self.root/'mfa-waiting-for-lock';process=None
  try:
   with self.keeper():
    process=subprocess.Popen(['php',str(self.php),'login'],env={**os.environ,
      'FIXTURE_MFA_NOW':str(self.now),'FIXTURE_MODULE':str(ROOT/'slsmassnotifyserver'),
      'FIXTURE_DATA':str(self.data),'FIXTURE_MFA_LOCK_SIGNAL':str(signal)},
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    deadline=time.monotonic()+4
    while not signal.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(0.01)
    self.assertTrue(signal.exists(),'Real PHP login did not reach the settings mutex')
    self.assertIsNone(process.poll(),'MFA writer bypassed the held keeper mutex')
    result=self.run_guard('exit',already_locked=True);self.assertEqual(result.returncode,0,result.stderr)
    self.assertIsNone(process.poll(),'MFA writer ran before recovery released the mutex')
   stdout,stderr=process.communicate(timeout=10)
   self.assertEqual(process.returncode,0,stderr);reply=json.loads(stdout)
   self.assertTrue(reply['accepted']);self.assertEqual(reply['counter'],consumed['counter']+1)
   state=self.settings();self.assertEqual(state['active']['immediate_config_revisions']['operator_access'],13)
   self.assertEqual(state['active']['operator_access'],state['pending']['operator_access'])
   self.assertFalse(self.run_php('login',consumed['code'])['accepted'])
  finally:
   if process is not None and process.poll() is None:process.kill();process.communicate(timeout=5)

 @contextlib.contextmanager
 def protected_completed_mfa_transaction(self):
  """Reuse real ephemeral publisher signatures, never mock authentication.

  This exercises the terminal library/archive contract after configuration
  restoration; the factory's unrelated history report is never approved/used.
  Full native history and module recovery belong to the separate VM gate.
  """
  spec=importlib.util.spec_from_file_location('mfa_signed_transaction_fixture',ROOT/'tools/test_installer_history_review.py')
  fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)
  fixture=fixture_module.HistoryReview(methodName='runTest');fixture.setUp()
  self.addCleanup(fixture.doCleanups)
  transaction=fixture.transaction;recovery=fixture.recovery;journal=fixture_module.j
  try:
   self.assertTrue(self.run_php('login')['accepted']);expected=self.settings()
   for name,body in self.original_snapshots.items():
    path=transaction/name;path.write_bytes(body);path.chmod(0o600)
   original_hash=hashlib.sha256(self.original_snapshots['config.snapshot']).hexdigest()
   pending_hash=hashlib.sha256(self.original_snapshots['pending.snapshot']).hexdigest()
   settings={**fixture.settings,'CONFIG_SNAPSHOT':str(transaction/'config.snapshot'),
    'CONFIG_HASH_BEFORE':original_hash,'PENDING_CONFIG_STATE':'present',
    'PENDING_CONFIG_PATH':str(self.data/'mass-notifications.pending.config'),
    'PENDING_CONFIG_SNAPSHOT':str(transaction/'pending.snapshot'),'PENDING_CONFIG_HASH':pending_hash}
   journal.update(transaction,'recovery_failed',settings)
   # A real authenticated installer may have published a write intent and then
   # died before applying it. Its afterimage remains part of archive authority.
   intention=self.crypto.decode_config(self.original_snapshots['config.snapshot'])
   intention['installer_fixture_intent']='prepared before mutation'
   image=self.crypto.encode_config(intention);image_hash=hashlib.sha256(image).hexdigest()
   journal.record_configuration_intent(recovery,original_hash,self.original_snapshots['config.snapshot'],image)
   with self.keeper():
    targets=journal.prepare_configuration_recovery(recovery,original_hash,transaction/'config.snapshot',
      self.data/'mass-notifications.config','present',pending_hash,transaction/'pending.snapshot',
      self.data/'mass-notifications.pending.config')
    restored=subprocess.run(['bash','-c',
      'source "$1"\nsafe_config_restore "$2" "$3" && safe_config_restore "$4" "$5"',
      'fixture',str(ROOT/'tools/install_release.sh'),targets['active_snapshot'],
      str(self.data/'mass-notifications.config'),targets['pending_snapshot'],
      str(self.data/'mass-notifications.pending.config')],capture_output=True,text=True,timeout=15)
    self.assertEqual(restored.returncode,0,restored.stderr)
    self.assertEqual(self.settings(),expected)
    journal.update(transaction,'rolled_back',settings,preserve_recovery_evidence=True)
   completed=journal.state(transaction)
   self.assertEqual(completed['phase'],'rolled_back')
   self.assertTrue(completed['recovery_evidence']['original_evidence_preserved'])
   self.assertEqual(completed['mfa_recovery']['kind'],'preserved_monotonic_mfa_consumption')
   self.assertEqual(completed['mfa_recovery']['original_active_sha256'],original_hash)
   self.assertEqual(completed['mfa_recovery']['original_pending_sha256'],pending_hash)
   self.assertEqual(completed['mfa_recovery']['active_sha256'],targets['active_sha256'])
   self.assertEqual(completed['mfa_recovery']['pending_sha256'],targets['pending_sha256'])
   self.assertEqual(completed['mfa_recovery']['intent_images'][image_hash],image_hash)
   yield journal,fixture,targets,recovery/('configuration-intent-'+image_hash+'.snapshot')
  finally:fixture.doCleanups()

 def test_authenticated_terminal_transaction_retains_mfa_evidence_on_next_begin(self):
  with self.protected_completed_mfa_transaction() as (journal,fixture,targets,image):
   self.assertTrue(journal.preserve_completed_evidence(journal.state(fixture.transaction)))
   before={str(path):path.read_bytes() for path in fixture.transaction.rglob('*') if path.is_file()}
   next_transaction=journal.begin(fixture.root)
   self.assertNotEqual(next_transaction,fixture.transaction)
   for path,body in before.items():self.assertEqual(Path(path).read_bytes(),body)

 def test_terminal_archive_tampering_refuses_pruning_without_deleting_evidence(self):
  for component in ['original','target','intention']:
   with self.subTest(component=component):
    # Each subcase needs genuinely unfinished source settings and signatures.
    # Earlier cases restored identical plaintext, so restore only our original
    # synthetic settings before issuing the next real PHP login.
    for kind,name in [('config.snapshot','mass-notifications.config'),('pending.snapshot','mass-notifications.pending.config')]:
     (self.data/name).write_bytes(self.original_snapshots[kind]);(self.data/name).chmod(0o640)
    with self.protected_completed_mfa_transaction() as (journal,fixture,targets,image):
     victim={'original':fixture.transaction/'config.snapshot','target':Path(targets['active_snapshot']),'intention':image}[component]
     victim.write_bytes(victim.read_bytes()+b'tampered');victim.chmod(0o600)
     before={str(path):path.read_bytes() for path in fixture.transaction.rglob('*') if path.is_file()}
     with self.assertRaises(journal.TransactionError):journal.begin(fixture.root)
     for path,body in before.items():self.assertEqual(Path(path).read_bytes(),body)

 def test_reduced_counter_after_durable_preservation_is_not_accepted(self):
  consumed=self.run_php('login');self.assertTrue(consumed['accepted'])
  self.assertEqual(self.run_guard('crash-after-targets').returncode,-9)
  state=self.settings()
  for kind in ['active','pending']:state[kind]['operator_access']['accounts'][0]['auth']['totp_last_counter']=consumed['counter']-1
  self.write_settings(state);before=self.encrypted_bytes();result=self.run_guard('exit')
  self.assertNotEqual(result.returncode,0,result.stderr)
  self.assertEqual(self.encrypted_bytes(),before);self.assert_originals_preserved()

 def test_non_mfa_changes_are_refused_without_restoration(self):
  baseline=self.settings();consumed=self.run_php('login');self.assertTrue(consumed['accepted']);advanced=self.settings()
  sealed=self.run_php('different-secret')['sealed']
  cases=[]
  def case(name,path,value,start=advanced):
   state=copy.deepcopy(start)
   for kind in ['active','pending']:
    target=state[kind]
    for part in path[:-1]:target=target[part]
    target[path[-1]]=value
   cases.append((name,state))
  auth=['operator_access','accounts',0,'auth']
  case('changed-secret',auth+['totp_secret_enc'],sealed)
  case('changed-password',auth+['password_hash'],'pbkdf2-sha256:600000:'+('0'*64)+':'+('1'*64))
  case('changed-credential-version',auth+['version'],'f'*64)
  case('changed-permissions',['operator_access','accounts',0,'channels'],['desktop_client_ids'])
  case('changed-recovery-codes',auth+['recovery_hashes'],[])
  case('changed-passkeys',auth+['passkeys'],[])
  case('changed-provider-secret',['provider_fixture','secret'],'changed-synthetic-provider-secret')
  case('new-desktop-key',['desktop_auth_key'],'eA=='*16)
  case('counter-bool',auth+['totp_last_counter'],True)
  case('counter-float',auth+['totp_last_counter'],float(consumed['counter']))
  case('counter-string',auth+['totp_last_counter'],str(consumed['counter']))
  case('counter-below-original',auth+['totp_last_counter'],baseline['active']['operator_access']['accounts'][0]['auth']['totp_last_counter']-1)
  case('revision-bool',['immediate_config_revisions','operator_access'],True)
  case('revision-float',['immediate_config_revisions','operator_access'],12.0)
  case('revision-alone',['immediate_config_revisions','operator_access'],12,start=baseline)
  case('other-bool-to-int',['unrelated_active','enabled'],1)
  case('other-int-to-float',['unrelated_active','number'],7.0)
  reorder=copy.deepcopy(advanced)
  for kind in ['active','pending']:reorder[kind]['operator_access']['accounts'].reverse()
  cases.append(('account-reorder',reorder))
  pending_drift=copy.deepcopy(advanced);pending_drift['pending']['pending_only']['preserve']='unapproved edit'
  cases.append(('pending-only-staged-edit',pending_drift))
  active_drift=copy.deepcopy(advanced);active_drift['active']['unrelated_active']['number']=8
  cases.append(('active-only-setting-edit',active_drift))
  for name,state in cases:
   with self.subTest(change=name):
    self.write_settings(state);before=self.encrypted_bytes();result=self.run_guard('exit')
    self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
    self.assertEqual(self.encrypted_bytes(),before)
    self.assertFalse((self.root/'trace').exists(),'Unexpected static restoration')
    self.assert_originals_preserved()

 def test_actual_recovery_code_consumption_remains_an_unapproved_change(self):
  consumed=self.run_php('login','11111111-22222222-33333333-44444444');self.assertTrue(consumed['accepted'])
  before=self.encrypted_bytes();result=self.run_guard('exit')
  self.assertNotEqual(result.returncode,0,result.stderr);self.assertEqual(self.encrypted_bytes(),before);self.assert_originals_preserved()

 def test_unsafe_mfa_receipt_is_refused_before_restore(self):
  self.assertTrue(self.run_php('login')['accepted']);self.assertEqual(self.run_guard().returncode,0)
  receipt=self.transaction/'recovery/configuration-mfa-recovery.json';receipt.chmod(0o644)
  before=self.encrypted_bytes();result=self.run_guard('exit')
  self.assertNotEqual(result.returncode,0,result.stderr);self.assertEqual(self.encrypted_bytes(),before);self.assert_originals_preserved()

 def partial_immediate(self,point,expected_exit):
  result=self.php_process('login',extra_env={'FIXTURE_PARTIAL_COMMIT':point})
  self.assertEqual(result.returncode,expected_exit,result.stderr)
  self.assertTrue((self.data/'.sls-immediate-settings-transaction.json').exists())
  before=self.encrypted_bytes();result=self.run_guard('exit')
  self.assertNotEqual(result.returncode,0,result.stderr);self.assertEqual(self.encrypted_bytes(),before);self.assert_originals_preserved()

 def test_unfinished_real_immediate_commit_before_pending_is_refused(self):
  self.partial_immediate('before',77)

 def test_unfinished_real_immediate_commit_after_both_writes_is_refused(self):
  self.partial_immediate('after',78)
if __name__=='__main__':unittest.main()
