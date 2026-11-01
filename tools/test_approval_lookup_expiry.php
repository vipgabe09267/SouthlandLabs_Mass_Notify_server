<?php
declare(strict_types=1);
if (getenv('SLS_TEST_NAMESPACE') !== 'entered') { throw new RuntimeException('Use isolated wrapper.'); }
require_once __DIR__.'/../slsmassnotifyserver/EnterpriseApprovalService.php';
use SLS\MassNotify\{EnterpriseOperationsConfig,EnterpriseOperationsStore,EnterpriseApprovalService};
function assertApprovalBoundary(bool $value,string $label):void { if(!$value){throw new RuntimeException($label);} }
$base=sys_get_temp_dir().'/sls-approval-expiry-'.bin2hex(random_bytes(8));mkdir($base,0700);
register_shutdown_function(static function()use($base):void{if(!is_dir($base)){return;}$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as $f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($base);});
$policy=['id'=>'approval_'.str_repeat('a',24),'name'=>'Private review','enabled'=>true,'channels'=>['phones'],'approver_ids'=>['pbx:alice','pbx:bob'],'expires_seconds'=>60];
$settings=['enterprise_operations'=>array_replace(EnterpriseOperationsConfig::defaults(),['enabled'=>true,'dual_approval'=>['enabled'=>true,'policies'=>[$policy]]])];
$request=['phones'=>['1001'],'title'=>'Inert review fixture','message'=>'No transport is present.'];
$failures=[];
foreach(['unchanged','slow_lookup_before_expiry','expires_at_lookup_boundary','expires_during_identity_lookup','already_expired','revoked_approver','rollback_during_lookup'] as $case){
 $clock=100000;$store=new EnterpriseOperationsStore($base.'/'.$case);$service=new EnterpriseApprovalService($store,static function()use(&$clock):int{return $clock;});
 $review=$service->request($settings,$request,'pbx:alice','alice-identity');$service->approve($review['review_id'],$settings,'pbx:bob',static fn()=>true,'bob-identity');
 $approved=$service->claim($review['review_id'],$settings,'pbx:bob',static fn()=>true);$lookups=0;$threw=false;
 if($case==='already_expired'){$clock+=61;}
 if(in_array($case,['expires_at_lookup_boundary','expires_during_identity_lookup'],true)){$clock+=59;}
 try{$allowed=$service->permits($settings,$approved,static function($person,$frozen,$identity)use(&$clock,&$lookups,$case):bool{
  ++$lookups;
  if($lookups===1&&$case==='expires_during_identity_lookup'){$clock+=2;}
  if($lookups===1&&$case==='expires_at_lookup_boundary'){$clock+=1;}
  if($lookups===1&&$case==='slow_lookup_before_expiry'){$clock+=10;}
  if($lookups===1&&$case==='rollback_during_lookup'){$clock--;}
  return !($case==='revoked_approver'&&$person==='pbx:bob');
 });}catch(DomainException $error){$threw=true;$allowed=false;}
 $state=$store->transaction(static fn(array &$state):array=>$state);
 $observed=['case'=>$case,'clock_after'=>$clock,'expires_at'=>100060,'identity_lookups'=>$lookups,'allowed'=>$allowed,'threw'=>$threw,'review_state'=>$state['approvals'][$review['review_id']]['state']];
 echo 'SLS_APPROVAL_LOOKUP '.json_encode($observed,JSON_THROW_ON_ERROR)."\n";
 $correct=$allowed===in_array($case,['unchanged','slow_lookup_before_expiry'],true)&&($case!=='already_expired'||$lookups===0)&&($case!=='rollback_during_lookup'||$threw)&&$observed['review_state']==='submitting';
 if(!$correct){$failures[]=$case;}
}
assertApprovalBoundary(!$failures,'Approval lookup deadline/clock boundary failed: '.implode(',',$failures));
