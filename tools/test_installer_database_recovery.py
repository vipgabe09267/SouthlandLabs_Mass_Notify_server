#!/usr/bin/env python3
"""Execute the installer's actual PHP recovery code against a private DB adapter."""
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'tools/install_release.sh').read_text()
SNAPSHOT=SOURCE.split('prepare_install_recovery() {',1)[1].split("php -r '\n",1)[1].split("\n' >",1)[0]
RESTORE=SOURCE.split('restore_module_registration() {',1)[1].split("php -r '\n",1)[1].split("\n' <",1)[0]
HARNESS=r'''<?php
$GLOBALS['fixture']=json_decode(file_get_contents(getenv('FIXTURE_STATE')),true,64,JSON_THROW_ON_ERROR);
function saveFixture(){file_put_contents(getenv('FIXTURE_STATE'),json_encode($GLOBALS['fixture'],JSON_THROW_ON_ERROR));}
class FakeStatement {
 private $sql; private $rows=[]; private $affected=0;
 function __construct($sql){$this->sql=$sql;}
 function execute($args){
  $s=&$GLOBALS['fixture']; $sql=$this->sql; $this->affected=0;
  if ($sql==='SHOW TABLES LIKE ?') {$this->rows=$args[0]==='manager' && ($s['manager_table']??true)===false?[]:[[$args[0]]]; return true;}
  if ($sql==='SELECT enabled FROM modules WHERE modulename = ?') {$this->rows=[[1]]; return true;}
  if(preg_match('/^SELECT \* FROM (modules|recordings|manager) WHERE (modulename|filename|name|manager_id) = \?/', $sql,$m)){
   $this->rows=array_values(array_filter($s[$m[1]],static fn($r)=>(string)$r[$m[2]]===(string)$args[0])); return true;
  }
  if(str_starts_with($sql,'DELETE FROM manager WHERE manager_id = ? AND name = ? AND secret = ?')){
   $columns=['manager_id','name','secret','deny','permit','read','write','writetimeout'];
   $previous=count($s['manager']);
   $s['manager']=array_values(array_filter($s['manager'],static function($row)use($columns,$args){
    foreach($columns as $i=>$key){if((string)$row[$key]!== (string)$args[$i]){return true;}}
    return false;
   }));
   $this->affected=$previous-count($s['manager']);return true;
  }
  if(preg_match('/^DELETE FROM (modules|recordings|manager) WHERE (modulename|filename|name) = \?$/',$sql,$m)){
   $s[$m[1]]=array_values(array_filter($s[$m[1]],static fn($r)=>$r[$m[2]]!==$args[0])); return true;
  }
  if(preg_match('/^INSERT INTO (modules|recordings|manager) \(([^)]+)\) VALUES /',$sql,$m)){
   $columns=array_map(static fn($v)=>trim($v,'`'),explode(',',$m[2]));
   $s[$m[1]][]=array_combine($columns,$args); return true;
  }
  throw new RuntimeException('Unexpected query: '.$sql);
 }
 function fetchColumn(){return $this->rows[0][0]??false;}
 function fetch($mode=null){return $this->rows[0]??false;}
 function fetchAll($mode=null){return $this->rows;}
 function rowCount(){return $this->affected;}
}
class FakeDatabase {
 private $saved;
 function prepare($sql){return new FakeStatement($sql);}
 function beginTransaction(){$this->saved=$GLOBALS['fixture'];}
 function commit(){saveFixture();$this->saved=null;}
 function rollBack(){$GLOBALS['fixture']=$this->saved;$this->saved=null;}
 function inTransaction(){return $this->saved!==null;}
}
class FakeBackup {
 function getAll($key){return $GLOBALS['fixture']['backup'][$key]??[];}
 function setConfig($key,$value,$id){$GLOBALS['fixture']['backup'][$id][$key]=$value;saveFixture();}
 function delConfig($key,$id){unset($GLOBALS['fixture']['backup'][$id][$key]);saveFixture();}
}
class FakeDashboard {function getConfig($key){return [];} function setConfig($key,$value){if($key==='allhooks'){file_put_contents(getenv('FIXTURE_TRACE'),"dashboard-hooks\n",FILE_APPEND);}}}
class FakeManager {
 function genConfig(){return ['unrelated.conf'=>['never'=>'write this file'],'manager_additional.conf'=>['native'=>'current manager database']];}
 function writeConfig($config){
  if($GLOBALS['fixture']['manager_write_failure']??false) {throw new RuntimeException('Fixture native Manager write failure');}
  $GLOBALS['fixture']['manager_written_files']=array_keys($config);saveFixture();
 }
}
class DashboardHooks {static function genHooks($order){return [];}}
class FreePBX {
 static function Database(){static $db;return $db??($db=new FakeDatabase());}
 static function Create(){return (object)['Backup'=>new FakeBackup()];}
 static function Dashboard(){return new FakeDashboard();}
 static function Manager(){return new FakeManager();}
}
'''

class DatabaseRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sls-db-recovery-');self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.state=self.root/'state.json';self.harness=self.root/'freepbx.php';self.harness.write_text(HARNESS)
  self.original={'modules':[{'modulename':'slsmassnotifyserver','version':'old','enabled':'1'},{'modulename':'other','version':'untouched'}],
   'recordings':[{'id':'8','filename':'custom/NWS_alert','displayname':'NWS Alert','description':'Default Southland Servers NWS alert opening tone.'},{'id':'9','filename':'custom/user-message','displayname':'User message'}],
   'backup':{'backupList':{'job1':{},'job2':{},'files':{}},'modules_job1':{'core':True},'modules_job2':{'core':True,'slsmassnotifyserver':'0'},'modules_files':{}},
   'manager':[self.manager_row('fixture-secret',permissions='system,call,originate',identifier='1'),
              self.manager_row('unrelated-fixture-secret',name='other-manager',identifier='2')],
   'receipts':['keep-new-receipt']}
  self.state.write_text(json.dumps(self.original))
 def manager_row(self,secret,name='slsmassnotify',permissions='system,call,originate,reporting',identifier='99'):
  return {'manager_id':identifier,'name':name,'secret':secret,'deny':'0.0.0.0/0.0.0.0&::/0',
          'permit':'127.0.0.1/255.255.255.255&::1/128','read':permissions,'write':permissions,'writetimeout':'1000'}
 def intent(self,snapshot,secret='fixture-secret',name='slsmassnotify'):
  snapshot['ami_intent']={'schema':1,'username':name,'secret_sha256':hashlib.sha256(secret.encode()).hexdigest()}
  return snapshot
 def run_php(self,code,stdin='',names=('slsmassnotify','sls_mass_notify')):
  import os
  code=code.replace('/etc/freepbx.conf',str(self.harness)).replace('/var/www/html/admin/modules/dashboard/classes/DashboardHooks.class.php',str(self.harness))
  return subprocess.run(['php','-r',code],input=stdin,text=True,capture_output=True,timeout=10,env={**os.environ,'FIXTURE_STATE':str(self.state),'FIXTURE_TRACE':str(self.root/'trace'),'SLS_RECOVERY_AMI_NAMES':json.dumps(names)})
 def snapshot(self):
  result=self.run_php(SNAPSHOT);self.assertEqual(result.returncode,0,result.stderr);return json.loads(result.stdout)
 def test_snapshot_query_failure_cannot_reach_explicit_success(self):
  self.harness.write_text(HARNESS.replace('$s=&$GLOBALS[\'fixture\']; $sql=$this->sql;', '$s=&$GLOBALS[\'fixture\']; $sql=$this->sql; throw new RuntimeException("Fixture database read failed");'))
  result=self.run_php(SNAPSHOT)
  self.assertNotEqual(result.returncode,0)
  with self.assertRaises(ValueError):json.loads(result.stdout)
  self.assertEqual(json.loads(self.state.read_text()),self.original)
 def test_scoped_restore_preserves_unrelated_jobs_and_new_operational_records(self):
  snapshot=self.snapshot();current=json.loads(self.state.read_text())
  current['modules'][0]['version']='candidate'
  current['recordings']=[current['recordings'][1],{'id':'10','filename':'custom/SLS_Mass_Notify_NWS_Alert','displayname':'SLS Mass Notify - NWS Alert','description':'Default Southland Servers NWS alert opening tone.'}]
  current['backup']['modules_job1'].update({'slsmassnotifyserver':True,'new-module':True})
  current['backup']['modules_job2']['slsmassnotifyserver']=True
  current['backup']['backupList']['new-job']={};current['backup']['modules_new-job']={'core':True,'slsmassnotifyserver':True}
  current['receipts'].append('receipt-during-install');self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  restored=json.loads(self.state.read_text())
  self.assertEqual(next(x for x in restored['modules'] if x['modulename']=='slsmassnotifyserver')['version'],'old')
  self.assertEqual(sorted(restored['recordings'],key=lambda r:r['id']),self.original['recordings'])
  self.assertEqual(restored['backup']['modules_job1'],{'core':True,'new-module':True})
  self.assertEqual(restored['backup']['modules_job2']['slsmassnotifyserver'],'0')
  self.assertTrue(restored['backup']['modules_new-job']['slsmassnotifyserver'])
  self.assertEqual(restored['receipts'],['keep-new-receipt','receipt-during-install'])
 def test_independent_existing_recording_edit_refuses_transaction(self):
  snapshot=self.snapshot();current=json.loads(self.state.read_text());current['recordings'][0]['displayname']='Administrator changed';self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertNotEqual(result.returncode,0)
  self.assertEqual(json.loads(self.state.read_text()),current)
 def test_rebrand_recording_label_change_rolls_back_with_original_id_and_references(self):
  original=json.loads(self.state.read_text())
  original['recordings'].append({'id':'12','filename':'custom/SLS_Mass_Notify_NWS_Alert','displayname':'SLS Mass Notify - NWS Alert','description':'Default Southland Servers NWS alert opening tone.'})
  self.state.write_text(json.dumps(original));snapshot=self.snapshot()
  current=json.loads(self.state.read_text());current['recordings'][-1].update({'displayname':'SLL Mass Notify Server - NWS Alert','description':'Default Southland Labs NWS alert opening tone.'})
  self.state.write_text(json.dumps(current));result=self.run_php(RESTORE,json.dumps(snapshot))
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(json.loads(self.state.read_text())['recordings'],original['recordings'])
 def test_new_brand_recording_added_during_failed_install_is_removed_by_scoped_restore(self):
  snapshot=self.snapshot();current=json.loads(self.state.read_text())
  current['recordings'].append({'id':'12','filename':'custom/SLS_Mass_Notify_NWS_Alert','displayname':'SLL Mass Notify Server - NWS Alert','description':'Default Southland Labs NWS alert opening tone.'})
  self.state.write_text(json.dumps(current));result=self.run_php(RESTORE,json.dumps(snapshot))
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(json.loads(self.state.read_text())['recordings'],self.original['recordings'])
 def test_removed_job_and_independent_enrollment_edit_are_preserved(self):
  snapshot=self.snapshot();current=json.loads(self.state.read_text());del current['backup']['backupList']['job1'];current['backup']['modules_job2']['slsmassnotifyserver']='administrator-edit';self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  restored=json.loads(self.state.read_text());self.assertNotIn('job1',restored['backup']['backupList']);self.assertEqual(restored['backup']['modules_job2']['slsmassnotifyserver'],'administrator-edit')
 def test_unscoped_or_invalid_identifier_snapshot_is_rejected(self):
  for change in ('filename','column'):
   snapshot=self.snapshot()
   if change=='filename':snapshot['recordings']['custom/user-message']=[]
   else:snapshot['row']['evil`']=1
   result=self.run_php(RESTORE,json.dumps(snapshot));self.assertNotEqual(result.returncode,0)
   self.assertEqual(json.loads(self.state.read_text()),self.original)

 def test_failed_fresh_install_removes_only_its_new_owned_ami_account(self):
  before=json.loads(self.state.read_text());before['manager']=before['manager'][1:];self.state.write_text(json.dumps(before))
  snapshot=self.intent(self.snapshot(),secret='new-fixture-secret')
  current=json.loads(self.state.read_text());current['manager'].append(self.manager_row('new-fixture-secret'))
  current['receipts'].append('receipt-after-admission');self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  after=json.loads(self.state.read_text());self.assertEqual(after['manager'],before['manager'])
  self.assertEqual(after['receipts'],current['receipts'])
  self.assertEqual(after['manager_written_files'],['manager_additional.conf'])

 def test_empty_backup_enrollment_still_refreshes_the_restored_dashboard_hooks(self):
  before=json.loads(self.state.read_text());before['backup']['backupList']={};self.state.write_text(json.dumps(before))
  snapshot=self.snapshot();self.assertEqual(snapshot['backup_enrollment'],[])
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual((self.root/'trace').read_text(),'dashboard-hooks\n')

 def test_failed_upgrade_restores_the_exact_previous_ami_row(self):
  snapshot=self.intent(self.snapshot())
  current=json.loads(self.state.read_text());current['manager'][0]=self.manager_row('fixture-secret')
  current['manager'].append(self.manager_row('new-independent-secret',name='new-independent',identifier='3'))
  self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  after=json.loads(self.state.read_text())
  self.assertEqual(next(r for r in after['manager'] if r['name']=='slsmassnotify'),self.original['manager'][0])
  self.assertEqual([r for r in after['manager'] if r['name']!='slsmassnotify'],current['manager'][1:])
  self.assertEqual(after['manager_written_files'],['manager_additional.conf'])

 def test_failure_between_ami_delete_and_recreation_restores_the_prior_row(self):
  snapshot=self.intent(self.snapshot())
  current=json.loads(self.state.read_text());current['manager']=current['manager'][1:];self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  restored=json.loads(self.state.read_text())['manager']
  self.assertEqual(sorted(restored,key=lambda r:r['name']),sorted(self.original['manager'],key=lambda r:r['name']))

 def test_legacy_ami_alias_migration_is_rolled_back_without_other_accounts(self):
  before=json.loads(self.state.read_text());before['manager'][0]['name']='sls_mass_notify';self.state.write_text(json.dumps(before))
  result=self.run_php(SNAPSHOT,names=('custom-paging','sls_mass_notify'))
  self.assertEqual(result.returncode,0,result.stderr)
  snapshot=self.intent(json.loads(result.stdout),name='custom-paging')
  current=json.loads(self.state.read_text());current['manager']=current['manager'][1:]+[self.manager_row('fixture-secret',name='custom-paging')]
  self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  after=json.loads(self.state.read_text())
  self.assertEqual(sorted(after['manager'],key=lambda r:r['name']),sorted(before['manager'],key=lambda r:r['name']))

 def test_independent_ami_credential_or_permission_edits_are_not_overwritten(self):
  snapshot=self.intent(self.snapshot())
  for change in ('secret','read','permit'):
   current=json.loads(json.dumps(self.original));current['manager'][0]=self.manager_row('fixture-secret')
   current['manager'][0][change]='independent-administrator-edit';current['receipts'].append('keep-current-receipt')
   self.state.write_text(json.dumps(current))
   result=self.run_php(RESTORE,json.dumps(snapshot))
   self.assertNotEqual(result.returncode,0,change)
   self.assertEqual(json.loads(self.state.read_text()),current)

 def test_recovery_retries_native_ami_render_after_a_post_commit_file_failure(self):
  snapshot=self.intent(self.snapshot());current=json.loads(self.state.read_text())
  current['manager'][0]=self.manager_row('fixture-secret');current['manager_write_failure']=True;self.state.write_text(json.dumps(current))
  first=self.run_php(RESTORE,json.dumps(snapshot));self.assertNotEqual(first.returncode,0)
  after=json.loads(self.state.read_text());self.assertEqual(next(r for r in after['manager'] if r['name']=='slsmassnotify'),self.original['manager'][0])
  after['manager_write_failure']=False;self.state.write_text(json.dumps(after))
  second=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(second.returncode,0,second.stderr)
  self.assertEqual(json.loads(self.state.read_text())['manager_written_files'],['manager_additional.conf'])

 def test_legacy_schema_two_recovery_does_not_invent_an_ami_snapshot(self):
  snapshot=self.snapshot();snapshot['schema']=2
  snapshot.pop('ami_names',None);snapshot.pop('ami_rows',None);snapshot.pop('ami_table_present',None)
  current=json.loads(self.state.read_text());current['manager'][0]=self.manager_row('fixture-secret');self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(json.loads(self.state.read_text())['manager'],current['manager'])

 def test_corrupt_or_unscoped_ami_recovery_metadata_changes_nothing(self):
  for change in ('names','row','intent'):
   snapshot=self.intent(self.snapshot())
   if change=='names':snapshot['ami_names']=['slsmassnotify','other-manager']
   elif change=='row':snapshot.setdefault('ami_rows',{})['slsmassnotify']=[self.manager_row('fixture-secret',name='other-manager')]
   else:snapshot['ami_intent']['secret_sha256']='invalid'
   result=self.run_php(RESTORE,json.dumps(snapshot));self.assertNotEqual(result.returncode,0,change)
   self.assertEqual(json.loads(self.state.read_text()),self.original)

 def test_real_shell_retains_private_intent_and_preserves_snapshot_order_through_php(self):
  helpers=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
  spec=importlib.util.spec_from_file_location('registration_crypto_fixture',helpers/'sls_config_crypto.py')
  crypto=importlib.util.module_from_spec(spec);spec.loader.exec_module(crypto)
  recovery=self.root/'recovery';recovery.mkdir(mode=0o700)
  snapshot=self.snapshot();record=recovery/'module-registration.json'
  record.write_text(json.dumps(snapshot));record.chmod(0o600)
  config=self.root/'config';config.write_bytes(crypto.encode_config({'ami':{'username':'slsmassnotify','password':'fixture-secret'}}));config.chmod(0o600)
  current=json.loads(self.state.read_text());current['manager'][0]=self.manager_row('fixture-secret');self.state.write_text(json.dumps(current))
  caller=self.root/'installer.sh'
  caller.write_text(SOURCE.replace('/etc/freepbx.conf',str(self.harness)).replace(
   '/var/www/html/admin/modules/dashboard/classes/DashboardHooks.class.php',str(self.harness)))
  script='''source "$1"
INSTALL_BOOTSTRAP_DIR="$2"; TRANSACTION_TOOL="$2/sls_install_transaction.py"
CONFIG_FILE="$3/config"; RECOVERY_DIR="$3/recovery"; LOG_FILE="$3/restore.log"
php() { /usr/bin/php "$@"; }
prepare_module_ami_intent
registration_recovery_input >"$3/merged.json"
restore_module_registration
'''
  environment={**os.environ,'FIXTURE_STATE':str(self.state),'FIXTURE_TRACE':str(self.root/'trace')}
  result=subprocess.run(['bash','-c',script,'fixture',str(caller),str(helpers),str(self.root)],
   env=environment,capture_output=True,text=True,timeout=15)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr+(self.root/'restore.log').read_text())
  intent=recovery/'module-ami-intent.json';saved=intent.read_bytes();inode=intent.stat().st_ino
  self.assertEqual(intent.stat().st_mode&0o777,0o600)
  self.assertNotIn('fixture-secret',intent.read_text()+result.stdout+result.stderr)
  self.assertEqual(json.loads(saved)['secret_sha256'],hashlib.sha256(b'fixture-secret').hexdigest())
  merged=json.loads((self.root/'merged.json').read_text())
  self.assertEqual(list(merged['recordings']),list(snapshot['recordings']))
  self.assertEqual(merged['ami_intent'],json.loads(saved))
  after=json.loads(self.state.read_text());self.assertEqual(next(r for r in after['manager'] if r['name']=='slsmassnotify'),self.original['manager'][0])
  self.assertEqual(after['manager_written_files'],['manager_additional.conf'])
  repeated=subprocess.run(['bash','-c',script,'fixture',str(caller),str(helpers),str(self.root)],
   env=environment,capture_output=True,text=True,timeout=15)
  self.assertEqual(repeated.returncode,0,repeated.stderr)
  self.assertEqual((intent.stat().st_ino,intent.read_bytes()),(inode,saved))
  config.write_bytes(crypto.encode_config({'ami':{'username':'slsmassnotify','password':'changed-fixture-secret'}}))
  refused=subprocess.run(['bash','-c',script,'fixture',str(caller),str(helpers),str(self.root)],
   env=environment,capture_output=True,text=True,timeout=15)
  self.assertNotEqual(refused.returncode,0)
  self.assertEqual((intent.stat().st_ino,intent.read_bytes()),(inode,saved))

 def test_legacy_trimmed_ami_fields_match_the_native_manager_identity(self):
  helpers=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
  spec=importlib.util.spec_from_file_location('trimmed_registration_crypto_fixture',helpers/'sls_config_crypto.py')
  crypto=importlib.util.module_from_spec(spec);spec.loader.exec_module(crypto)
  config=self.root/'config'
  original=crypto.encode_config({'ami':{'username':' \tslsmassnotify \r\n','password':' \tfixture-secret \r\n'}})
  config.write_bytes(original);config.chmod(0o600)
  names_body=SOURCE.split("<<'PYAMINAMES'\n",1)[1].split('\nPYAMINAMES',1)[0]
  result=subprocess.run(['/usr/bin/python3','-I','-c',names_body,str(helpers/'sls_config_crypto.py'),str(config)],capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(json.loads(result.stdout),['slsmassnotify','sls_mass_notify'])
  recovery=self.root/'recovery';recovery.mkdir(mode=0o700)
  record=recovery/'module-registration.json';record.write_text(json.dumps(self.snapshot()));record.chmod(0o600)
  script='source "$1"; INSTALL_BOOTSTRAP_DIR="$2"; TRANSACTION_TOOL="$2/sls_install_transaction.py"; CONFIG_FILE="$3/config"; RECOVERY_DIR="$3/recovery"; prepare_module_ami_intent'
  result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),str(helpers),str(self.root)],capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr)
  intent=json.loads((recovery/'module-ami-intent.json').read_bytes())
  self.assertEqual(intent['username'],'slsmassnotify')
  self.assertEqual(intent['secret_sha256'],hashlib.sha256(b'fixture-secret').hexdigest())
  self.assertEqual(config.read_bytes(),original)

 def test_legacy_recovery_input_never_requires_a_new_intent_file(self):
  helpers=ROOT/'slsmassnotifyserver/bin/sls_mass_notify';recovery=self.root/'recovery';recovery.mkdir(mode=0o700)
  snapshot=self.snapshot();snapshot['schema']=2
  for name in ('ami_rows','ami_names','ami_table_present'):snapshot.pop(name)
  record=recovery/'module-registration.json';record.write_text(json.dumps(snapshot));record.chmod(0o600)
  (recovery/'module-ami-intent.json').write_bytes(b'irrelevant legacy evidence; never authorize it')
  script='source "$1"; TRANSACTION_TOOL="$2/sls_install_transaction.py"; RECOVERY_DIR="$3/recovery"; registration_recovery_input'
  result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),str(helpers),str(self.root)],
   capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(json.loads(result.stdout),snapshot)

 def test_ami_identifier_collision_preserves_the_independent_account(self):
  snapshot=self.intent(self.snapshot());current=json.loads(self.state.read_text())
  current['manager'][0]=self.manager_row('fixture-secret')
  current['manager'].append(self.manager_row('another-secret',name='independent-id-owner',identifier='1'))
  self.state.write_text(json.dumps(current))
  result=self.run_php(RESTORE,json.dumps(snapshot));self.assertNotEqual(result.returncode,0)
  self.assertEqual(json.loads(self.state.read_text()),current)

if __name__=='__main__':unittest.main()
