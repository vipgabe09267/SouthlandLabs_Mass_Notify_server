<?php
declare(strict_types=1);
namespace SLS\MassNotify { function time():int{return $GLOBALS['sls_current_operator_clock'];} }
namespace {
if(getenv('SLS_TEST_NAMESPACE')!=='entered'){throw new RuntimeException('Use isolated wrapper.');}
require_once __DIR__.'/../slsmassnotifyserver/Operators.php';
use SLS\MassNotify\OperatorAccess;
class FreePBX {}
class ampuser {
 public static array $row=[];public string $username;
 public function __construct(string $username,string $source='database'){$this->username=$username;}
 public function getAmpUser(string $username):array{
  $GLOBALS['sls_current_operator_lookups']++;
  if($GLOBALS['sls_current_operator_lookups']===2){$GLOBALS['sls_current_operator_clock']+=$GLOBALS['sls_current_operator_delay'];}
  $row=self::$row;
  if($GLOBALS['sls_current_operator_changed']&&$GLOBALS['sls_current_operator_lookups']===2){$row['password_sha1']=str_repeat('c',40);}
  return $row;
 }
}
class CurrentOperatorFixture {
 use \FreePBX\modules\SlsOperators;
 public array $settings=[];
 public function getActiveSettings():array{return$this->settings;}
}
$base=100000;$failures=[];$id='api_'.str_repeat('a',24);
foreach(['unchanged'=>[0,0,$base+5], 'slow_before_expiry'=>[0,2,$base+5],
 'expires_at_second_lookup'=>[4,1,$base+5], 'expires_during_second_lookup'=>[4,2,$base+5],
 'already_expired'=>[6,0,$base+5], 'unlimited'=>[0,10,0], 'trusted_pbx_administrator'=>[6,0,$base+5],
 'changed_identity'=>[0,0,$base+5]]as$case=>[$initial,$delay,$expiry]){
 $GLOBALS['sls_current_operator_clock']=$base+$initial;$GLOBALS['sls_current_operator_delay']=$delay;$GLOBALS['sls_current_operator_lookups']=0;$GLOBALS['sls_current_operator_changed']=$case==='changed_identity';
 unset($GLOBALS['sls_operator_portal_principal']);
 ampuser::$row=['id'=>42,'username'=>'private-operator','mode'=>'database','password_sha1'=>str_repeat('b',40),'sections'=>$case==='trusted_pbx_administrator'?['*']:['slsmassnotifyserver_operations']];
 $account=['id'=>$id,'username'=>'private-operator','source'=>'database','name'=>'Private operator','role'=>'sender','enabled'=>true,'expires_at'=>$expiry,'identity'=>OperatorAccess::identity(ampuser::$row),'personal_members'=>['extensions'=>['1001']]];
 $fixture=new CurrentOperatorFixture();$fixture->settings=['operator_access'=>['enabled'=>true,'accounts'=>[$account]],'control_api'=>['enabled'=>true,'credentials'=>[]]];$_SESSION=['AMP_user'=>new ampuser('private-operator')];
 $principal=null;try{$principal=$fixture->currentOperator();}catch(DomainException$error){}
 $observed=['case'=>$case,'clock_after'=>$GLOBALS['sls_current_operator_clock'],'expires_at'=>$expiry,'lookup_calls'=>$GLOBALS['sls_current_operator_lookups'],'returned_principal'=>$principal!==null,'principal_active_at_return'=>$principal!==null&&OperatorAccess::activeAccount($principal),'principal_id'=>$principal['id']??null];
 echo'SLS_CURRENT_OPERATOR_LOOKUP '.json_encode($observed,JSON_THROW_ON_ERROR)."\n";
 $expected=in_array($case,['unchanged','slow_before_expiry','unlimited','trusted_pbx_administrator'],true);
 if(($principal!==null)!==$expected||($case==='already_expired'&&$observed['lookup_calls']!==1)||($case==='trusted_pbx_administrator'&&$observed['principal_id']!=='recovery_admin')){$failures[]=$case;}
}
if($failures){throw new RuntimeException('currentOperator returned expired/mismatched principal: '.implode(',',$failures));}
}
