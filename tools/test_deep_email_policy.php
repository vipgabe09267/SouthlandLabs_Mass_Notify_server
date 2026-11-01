<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/slsmassnotifyserver/DeliveryAuthorization.php';
require_once dirname(__DIR__).'/slsmassnotifyserver/AutomationService.php';
use SLS\MassNotify\{DeliveryAuthorization as Policy,ApiSecurity,AutomationConfig,AutomationService,AutomationStore,IncidentConfig};
$checks=0;$check=static function($ok,$message)use(&$checks){$checks++;if(!$ok)throw new RuntimeException($message);};
$a='email_'.str_repeat('a',24);$b='email_'.str_repeat('b',24);$c='email_'.str_repeat('c',24);$now=time();
$settings=['runtime_enabled'=>true,'announcement_email'=>['enabled'=>'1','recipients'=>[
    ['id'=>$a,'name'=>'One','address'=>'one@example.com','enabled'=>'1'],
    ['id'=>$b,'name'=>'Two','address'=>'two@example.com','enabled'=>'1'],
    ['id'=>$c,'name'=>'Three','address'=>'three@example.com','enabled'=>'1']]],
    'mail_from_domain'=>'example.com','mail_from_name'=>'PBX'];
$context=['recipient_id'=>$a,'target_hashes'=>[Policy::emailTargetHash($settings,$a)],'expires_at'=>$now+300,'schedule_deadline'=>null];
$check(Policy::permitsEmail($settings,$context),'Local immutable email context rejected.');
foreach([['target_hashes'=>[str_repeat('0',64)]],['target_hashes'=>[]],['target_hashes'=>array_fill(0,4,str_repeat('0',64))],['target_hashes'=>[Policy::emailTargetHash($settings,$a),Policy::emailTargetHash($settings,$a)]],['expires_at'=>$now],['expires_at'=>true],['schedule_deadline'=>$now],['schedule_deadline'=>'later'],['recipient_id'=>$b],['unknown'=>true],['api_credential_id'=>null],['automation_context'=>null]]as$delta){
    $check(!Policy::permitsEmail($settings,array_replace($context,$delta)),'Invalid/expired email context accepted.');
}
$duplicate=$settings;$duplicate['announcement_email']['recipients'][]=$duplicate['announcement_email']['recipients'][0];
$check(Policy::emailTargetHash($duplicate,$a)==='','Duplicate route had an unambiguous projection.');
$issued=ApiSecurity::issue(['name'=>'Inert scoped sender','scopes'=>['send'],'audience'=>['unrestricted'=>false,'email_recipient_ids'=>[$a]]])['credential'];
$api=$settings;$api['control_api']=['enabled'=>'1','credentials'=>[$issued]];$gate=$context+['api_credential_id'=>$issued['id']];
$check(Policy::permitsEmail($api,$gate),'Scoped email permit rejected.');
$other=$gate;$other['recipient_id']=$b;$other['target_hashes']=[Policy::emailTargetHash($api,$b)];
$check(!Policy::permitsEmail($api,$other),'Scoped principal gained another saved recipient.');
$api['control_api']['credentials'][0]['expires_at']=$now-1;$check(!Policy::permitsEmail($api,$gate),'Expired principal retained email permit.');
$api['control_api']['credentials']=[];$check(!Policy::permitsEmail($api,$gate),'Revoked principal retained email permit.');
$operator=$issued;$operator['audience']['unrestricted']=true;$operator['allowed_channels']=['extensions'];
$check(!ApiSecurity::permitsResolvedAnnouncement($operator,['email_recipient_ids'=>[$a]],$settings),'Unrestricted operator bypassed channel policy.');
$root=sys_get_temp_dir().'/sls-email-policy-'.bin2hex(random_bytes(8));mkdir($root,0700);
try{
    $journal=$root.'/automations';mkdir($journal,0700);
    $template=IncidentConfig::template(['id'=>'tpl_'.str_repeat('d',24),'name'=>'Inert email template','title'=>'Fixture','message'=>'No provider calls',
        'delivery'=>['email_recipient_ids'=>[$a],'group_ids'=>['grp_one']]]);
    $rule=AutomationConfig::rule(['id'=>'trg_'.str_repeat('e',24),'name'=>'Inert sensor','enabled'=>true,'kind'=>'sensor','secret'=>str_repeat('f',64),'event'=>'fixture',
        'template_id'=>$template['id'],'allow_tests'=>true,'cooldown_seconds'=>10]);
    $automation=$settings;$automation['incident_workflows']=['schema'=>1,'templates'=>[$template]];
    $automation['announcement_groups']=[['id'=>'grp_one','email_recipient_ids'=>[$b]]];
    $automation['automations']=['schema'=>1,'rules'=>[$rule],'actions'=>[]];
    $store=new AutomationStore($journal);$service=new AutomationService($store,static fn()=>$automation,static function(){throw new RuntimeException('No notification allowed');},static function(){throw new RuntimeException('No action allowed');},static fn()=>$now);
    $event=$service->activate($rule['id'],['request_id'=>'private-email-policy','sent_at'=>$now,'expires_at'=>$now+300,'event'=>'fixture','message'=>'Inert','is_test'=>true],'sensor');
    foreach([$a=>true,$b=>true,$c=>false]as$id=>$expected){
        $emailGate=['recipient_id'=>$id,'target_hashes'=>[Policy::emailTargetHash($automation,$id)],'expires_at'=>$now+300,'schedule_deadline'=>null,'automation_context'=>$event['context']];
        $check(Policy::permitsEmail($automation,$emailGate,$journal,$now)===$expected,'Automation email template/group selection changed.');
    }
    $emailGate=$context+['automation_context'=>$event['context']];
    $changed=$automation;$changed['automations']['rules'][0]['enabled']=false;
    $check(!Policy::permitsEmail($changed,$emailGate,$journal,$now),'Disabled automation retained email authority.');
    $store->transaction(static function(array &$state)use($event){$state['events'][$event['id']]['blocked']=true;});
    $check(!Policy::permitsEmail($automation,$emailGate,$journal,$now),'Durably blocked automation retained email authority.');
    $check(!Policy::permits($settings,$context),'Typed email contract broadened legacy webhook contract.');
    echo "Typed email policy, original routing, principal expiry/revocation and real automation journal: $checks checks passed.\n";
}finally{
    foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST)as$path){$path->isDir()?rmdir((string)$path):unlink((string)$path);}rmdir($root);
}
