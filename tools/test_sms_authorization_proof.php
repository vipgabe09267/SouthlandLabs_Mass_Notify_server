<?php
declare(strict_types=1);
if(getenv('SLS_TEST_NAMESPACE')!=='entered'){throw new RuntimeException('Use unchanged isolated wrapper.');}
require dirname(__DIR__).'/slsmassnotifyserver/api/sls-mass-notify/sms/Service.php';
require dirname(__DIR__).'/slsmassnotifyserver/AnnouncementSms.php';
require dirname(__DIR__).'/slsmassnotifyserver/bin/sls_mass_notify/sls_runtime_state.php';
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
final class SmsProofProvider extends Provider{
 public int$calls=0;public bool$fail=false;
 protected function request(string$url,array$headers,string$body,?string$basic):array{$this->calls++;if($this->fail){throw new RuntimeException('Synthetic request uncertainty.');}return['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'SM'.str_repeat('b',32),'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];}
}
final class SmsProofBoundsModule{
 use \FreePBX\modules\SlsAnnouncementSms;
 public array$settings=[];public ?int$deadline=null;
 public function getActiveSettings():array{return$this->settings;}
 private function scheduledAnnouncementDeadline(array$request):?int{return$this->deadline;}
 private function weatherChannelAuthorization(array$context):array{return['status'=>'eligible','sms_recipient_ids'=>['sms_'.str_repeat('a',24)]];}
 private function automationContextPermitted(array$context):bool{return true;}
 public function authorization(array$request,string$id):bool|array{return$this->announcementSmsSubmissionPermitted($request,$id,hrtime(true));}
}
$root=sys_get_temp_dir().'/sls-sms-authorization-proof-'.bin2hex(random_bytes(8));mkdir($root,0700);$checks=0;
function check(bool$v,string$name):void{global$checks;$checks++;if(!$v){throw new RuntimeException($name);}}
try{
 $now=time();$id='sms_'.str_repeat('a',24);$settings=['public_pbx_host'=>'pbx.example.invalid','control_api'=>['base_url'=>'https://pbx.example.invalid/api/sls-mass-notify'],'announcement_sms'=>Config::normalize(['enabled'=>true,'provider'=>'twilio','from'=>'+15555550101','organization'=>'SLS','segment_cost_micros'=>10000,'twilio_account_sid'=>'AC'.str_repeat('a',32),'twilio_key_sid'=>'SK'.str_repeat('b',32),'twilio_key_secret'=>'inert','twilio_auth_token'=>str_repeat('c',32),'recipients'=>[['id'=>$id,'name'=>'Private target','number'=>'+15555550102','enabled'=>true,'consent'=>true,'consent_note'=>'Fixture','consent_at'=>gmdate('c',$now-3600)]]])];$frozen=Service::snapshot($settings,[$id],'Fixture','No actual SMS.',false)[$id];
 foreach(['valid','expired_wall','expired_monotonic','missing_bound','extra_field','wrong_boolean','throws','legacy_true','legacy_false','actual_request_uncertainty']as$case){
  $store=new Store($root.'/'.$case);$provider=new SmsProofProvider();$provider->fail=$case==='actual_request_uncertainty';$service=new Service($store,$provider,$root);$proof=['allowed'=>true,'valid_until'=>$now+900,'monotonic_until'=>hrtime(true)+78000000000];if($case==='expired_wall'){$proof['valid_until']=$now;}if($case==='expired_monotonic'){$proof['monotonic_until']=hrtime(true)-1;}if($case==='missing_bound'){unset($proof['valid_until']);}if($case==='extra_field'){$proof['extra']='no';}if($case==='wrong_boolean'){$proof['allowed']='true';}if($case==='legacy_true'){$proof=true;}if($case==='legacy_false'){$proof=false;}$authorizations=0;$authorize=static function()use($case,$proof,&$authorizations){$authorizations++;if($case==='throws'){throw new RuntimeException('Synthetic source read failed.');}return$proof;};
  $row=$service->send($settings,$frozen,'announcement-'.str_repeat('d',32),'job_'.str_repeat('e',32),$now+900,$now,'',$authorize);$submits=in_array($case,['valid','legacy_true','actual_request_uncertainty'],true);check($provider->calls===($submits?1:0),'Provider calls '.$case);check($row['state']===($case==='actual_request_uncertainty'?'uncertain':($submits?'accepted':'cancelled')),'Known/uncertain outcome '.$case);check($row['submission_started']===$submits,'Submission flag '.$case);
  $again=$service->send($settings,$frozen,'announcement-'.str_repeat('d',32),'job_'.str_repeat('e',32),$now+900,$now,'',$authorize);check($provider->calls===($submits?1:0)&&$authorizations===1&&$again['state']===$row['state'],'Consumed claim replay '.$case);foreach($store->stats($now)['periods']as$period){check((int)$period['segments']===1&&(int)$period['amount']===10000,'Budget retained '.$case);}
 }
 $module=new SmsProofBoundsModule();$module->settings=['runtime_enabled'=>true];
 foreach(['weather_source'=>['weather_context'=>['deadline_at'=>$now+600,'source_validity'=>['expires_at'=>$now+30]]],'automation'=>['automation_context'=>['expires_at'=>$now+40]],'weather_job'=>['weather_context'=>['deadline_at'=>$now+50]]]as$case=>$context){$expected=['weather_source'=>30,'automation'=>40,'weather_job'=>50][$case];$proof=$module->authorization(['sms_expires_at'=>$now+900]+$context,$id);check(is_array($proof)&&$proof['valid_until']===$now+$expected,'Immutable source deadline proof '.$case);}
 echo'SLS SMS authorization proof: '.$checks." actual strict-proof/outcome/replay/budget checks passed without provider traffic.\n";
}finally{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($root);}
