#!/usr/bin/python3
"""Actual signed trigger controller/trait/service; private config and inert actions only."""
import hashlib,hmac,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
if os.environ.get('SLS_TEST_NAMESPACE')!='entered':raise SystemExit('Use unchanged isolated wrapper.')
ROOT=Path(__file__).resolve().parents[1];API=ROOT/'slsmassnotifyserver/api/sls-mass-notify'
class TriggerRevisionBoundary(unittest.TestCase):
 def invoke(self,change='',signature_bad=False,operation='activate',repeat=False):
  with tempfile.TemporaryDirectory(prefix='sls-trigger-revision-')as folder:
   p=Path(folder);now=int(time.time());rule_id='trg_'+'b'*24;action_id='act_'+'a'*24
   rule={'id':rule_id,'name':'Private sensor','enabled':True,'kind':'sensor','secret':'c'*64,'event':'smoke','action_ids':[action_id],'allow_tests':True,'cooldown_seconds':10}
   action={'id':action_id,'name':'Inert output','enabled':True,'kind':'brightsign_udp','host':'192.168.1.20','port':5000,'message':'original'}
   if operation=='challenge':rule.pop('event');rule['kind']='panic';rule['location_id']='loc_000000000000000000000001'
   cfg={'runtime_enabled':True,'automations':{'schema':1,'rules':[rule],'actions':[action]},'enterprise_integrations':{'enabled':'1','sensors':{'enabled':'1'}}};(p/'config').write_text(json.dumps(cfg));(p/'config').chmod(0o640)
   body=json.dumps({'operation':'activate','request_id':'private-event','sent_at':now,'expires_at':now+300,'event':'smoke','message':'No real action.','is_test':True},separators=(',',':'))
   if operation=='challenge':body=json.dumps({'operation':'challenge','request_id':'2'*32},separators=(',',':'))
   if operation=='heartbeat':body=json.dumps({'operation':'heartbeat','request_id':'1'*32,'sent_at':now,'expires_at':now+60,'is_test':True},separators=(',',':'))
   signature=hmac.new(('c'*64).encode(),f'{rule_id}.{now}.{body}'.encode(),hashlib.sha256).hexdigest()
   inp={'server':{'REQUEST_METHOD':'POST','CONTENT_TYPE':'application/json','HTTPS':'on','REMOTE_ADDR':'127.0.0.1','HTTP_X_SLS_TIMESTAMP':str(now),'HTTP_X_SLS_SIGNATURE':'bad'if signature_bad else signature},'body':body,'rule_id':rule_id,'change':change};(p/'input').write_text(json.dumps(inp))
   bootstrap=r"""<?php
require_once MODULE_ROOT.'/Automations.php';
require_once MODULE_ROOT.'/EnterpriseIntegrations.php';
class TriggerFixtureModule {
 use \FreePBX\modules\SlsAutomations;
 use \FreePBX\modules\SlsEnterpriseIntegrations;
 private int $settingsReads=0;
 function getActiveSettings():array{$input=json_decode(file_get_contents(__DIR__.'/input'),true);$cfg=json_decode(file_get_contents(__DIR__.'/config'),true);if(++$this->settingsReads>=2&&$input['change']==='rotation_during_admission'){$cfg['automations']['rules'][0]['secret']=str_repeat('d',64);file_put_contents(__DIR__.'/config',json_encode($cfg));}return$cfg;}
 protected function enterpriseIntegrationsStoreDirectory():string{return __DIR__.'/integration-journal';}
 protected function automationStoreDirectory():string{return __DIR__.'/automation-journal';}
 private function startAutomationWorker(string$id):void{$this->automationService()->process($id);}
 private function runAutomationAction(array$action,array$event):array{file_put_contents(__DIR__.'/inert-effects',json_encode(['message'=>$action['message'],'revision'=>$event['context']['revision']])."\n",FILE_APPEND);return['state'=>'completed'];}
}
class FreePBX {
 static function create(){
  file_put_contents(__DIR__.'/bootstrapped','1');$input=json_decode(file_get_contents(__DIR__.'/input'),true);$cfg=json_decode(file_get_contents(__DIR__.'/config'),true);
  if($input['change']==='secret_rotation'){$cfg['automations']['rules'][0]['secret']=str_repeat('d',64);}
  if($input['change']==='rotation_and_new_action'){$cfg['automations']['rules'][0]['secret']=str_repeat('d',64);$cfg['automations']['actions'][0]['message']='new-approved-action';}
  if($input['change']==='action_changed_same_key'){$cfg['automations']['actions'][0]['message']='new-approved-action';}
  if($input['change']==='rule_disabled'){$cfg['automations']['rules'][0]['enabled']=false;}
  if($input['change']==='runtime_stopped'){$cfg['runtime_enabled']=false;}
  file_put_contents(__DIR__.'/config',json_encode($cfg));return(object)['Slsmassnotifyserver'=>new TriggerFixtureModule];
 }
}
"""
   (p/'bootstrap.php').write_text(bootstrap.replace('MODULE_ROOT',json.dumps(str(ROOT/'slsmassnotifyserver'))))
   source=(API/'trigger.php').read_text().replace('<?php','',1).replace('declare(strict_types=1);','',1).replace('__DIR__',json.dumps(str(API)))
   source=source.replace("'/var/www/html/admin/modules/slsmassnotifyserver/AutomationInputs.php'",json.dumps(str(ROOT/'slsmassnotifyserver/AutomationInputs.php'))).replace("'/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config'",json.dumps(str(p/'config'))).replace("'/etc/freepbx.conf'",json.dumps(str(p/'bootstrap.php')))
   prefix=r"""<?php
declare(strict_types=1);namespace TriggerControllerFixture;
use \RuntimeException;use \Throwable;use \DomainException;use \InvalidArgumentException;use \JsonException;
function file_get_contents($path,...$args){return$path==='php://input'?$GLOBALS['fixture_input']['body']:\file_get_contents($path,...$args);}
function http_response_code($code){$GLOBALS['fixture_status']=$code;}
function header($line){}
$GLOBALS['fixture_input']=json_decode(\file_get_contents(__DIR__.'/input'),true);$_SERVER=$GLOBALS['fixture_input']['server'];$_GET=['rule_id'=>$GLOBALS['fixture_input']['rule_id']];
ob_start();register_shutdown_function(static function(){echo json_encode(['status'=>$GLOBALS['fixture_status']??0,'body'=>json_decode(ob_get_clean(),true)]);});
"""
   (p/'endpoint.php').write_text(prefix+source)
   def request():
    r=subprocess.run(['php',str(p/'endpoint.php')],capture_output=True,text=True,timeout=8);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stderr,'');return json.loads(r.stdout)
   response=request()
   if repeat:
    self.assertEqual(response['status'],200,response)
    if change=='secret_rotation':self.fail('First call was intended to use unchanged enrollment.')
    current=json.loads((p/'config').read_text());current['automations']['rules'][0]['secret']='d'*64;(p/'config').write_text(json.dumps(current));inp['change']='';inp['server']['HTTP_X_SLS_SIGNATURE']=hmac.new(('d'*64).encode(),f'{rule_id}.{now}.{body}'.encode(),hashlib.sha256).hexdigest();(p/'input').write_text(json.dumps(inp));response=request()
   response['effects']=[json.loads(x)for x in(p/'inert-effects').read_text().splitlines()]if(p/'inert-effects').exists()else[];response['bootstrapped']=(p/'bootstrapped').exists();print('SLS_TRIGGER_BOOTSTRAP '+json.dumps({'case':change or('bad_signature'if signature_bad else'unchanged'),'operation':operation,'repeat_with_new_key':repeat,'response':response}),flush=True);return response
 def test_unchanged_source_and_action_submit_once(self):
  r=self.invoke();self.assertEqual(r['status'],200);self.assertEqual([x['message']for x in r['effects']],['original'])
 def test_invalid_signature_never_bootstraps(self):
  r=self.invoke(signature_bad=True);self.assertEqual(r['status'],403);self.assertFalse(r['bootstrapped']);self.assertEqual(r['effects'],[])
 def test_disabled_current_rule_still_refuses(self):
  r=self.invoke('rule_disabled');self.assertEqual(r['status'],422);self.assertEqual(r['effects'],[])
 def test_stopped_runtime_still_refuses(self):
  r=self.invoke('runtime_stopped');self.assertEqual(r['status'],422);self.assertEqual(r['effects'],[])
 def test_secret_rotated_during_bootstrap_cannot_authorize_new_event(self):
  r=self.invoke('secret_rotation');self.assertNotEqual(r['status'],200);self.assertEqual(r['effects'],[])
 def test_old_signature_cannot_bind_new_rule_revision_and_action(self):
  r=self.invoke('rotation_and_new_action');self.assertNotEqual(r['status'],200);self.assertEqual(r['effects'],[])
 def test_action_change_with_unchanged_current_key_admits_current_policy(self):
  r=self.invoke('action_changed_same_key');self.assertEqual(r['status'],200);self.assertEqual([x['message']for x in r['effects']],['new-approved-action'])
 def test_rotation_between_facade_and_actual_admission_refuses(self):
  r=self.invoke('rotation_during_admission');self.assertEqual(r['status'],422);self.assertEqual(r['effects'],[])
 def test_heartbeat_unchanged_and_after_rotation(self):
  r=self.invoke(operation='heartbeat');self.assertEqual(r['status'],200);self.assertEqual(r['body']['state'],'healthy');self.assertEqual(r['effects'],[])
  r=self.invoke('secret_rotation',operation='heartbeat');self.assertEqual(r['status'],422);self.assertEqual(r['effects'],[])
 def test_newly_signed_duplicate_after_rotation_keeps_original_outcome(self):
  r=self.invoke(repeat=True);self.assertEqual(r['status'],200);self.assertEqual(r['body']['state'],'complete');self.assertEqual([x['message']for x in r['effects']],['original'])
 def test_panic_challenge_current_enrollment_and_rotation(self):
  r=self.invoke(operation='challenge');self.assertEqual(r['status'],200);self.assertIn('confirmation',r['body']['challenge']);self.assertEqual(r['effects'],[])
  r=self.invoke('secret_rotation',operation='challenge');self.assertEqual(r['status'],422);self.assertEqual(r['effects'],[])
if __name__=='__main__':unittest.main()
