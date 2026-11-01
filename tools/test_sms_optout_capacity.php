<?php
declare(strict_types=1);
if(getenv('SLS_TEST_NAMESPACE')!=='entered'){throw new RuntimeException('Use isolated wrapper.');}
require_once __DIR__.'/../slsmassnotifyserver/api/sls-mass-notify/sms/Service.php';
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
class OptoutCapacityProvider extends Provider {
 public int $calls=0;
 protected function request(string $url,array $headers,string $body,?string $basic):array{
  $this->calls++;return['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'SM'.str_repeat('b',32),'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];
 }
}
$root=sys_get_temp_dir().'/sls-sms-optout-capacity-'.bin2hex(random_bytes(8));mkdir($root,0700);
register_shutdown_function(static function()use($root):void{if(!is_dir($root)){return;}$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($root);});
$id='sms_'.str_repeat('a',24);$now=time();$settings=['runtime_enabled'=>true,'public_pbx_host'=>'pbx.example.invalid','control_api'=>['base_url'=>'https://pbx.example.invalid/api/sls-mass-notify'],'announcement_sms'=>Config::normalize(['enabled'=>true,'provider'=>'twilio','message_format'=>'sms','from'=>'+15555550101','organization'=>'SLS','segment_cost_micros'=>10000,'twilio_account_sid'=>'AC'.str_repeat('a',32),'twilio_key_sid'=>'SK'.str_repeat('b',32),'twilio_key_secret'=>'inert-key','twilio_auth_token'=>str_repeat('c',32),'recipients'=>[['id'=>$id,'name'=>'Private recipient','number'=>'+15555550102','enabled'=>true,'consent'=>true,'consent_note'=>'Synthetic fixture','consent_at'=>gmdate('c',$now-3600)]]])];
$frozen=Service::snapshot($settings,[$id],'Fixture','No real provider is used.',false)[$id];$failures=[];
foreach(['ordinary_send'=>0,'near_capacity_send'=>99999,'signed_stop'=>0,'unrecordable_signed_stop'=>100000,'full_history_without_callback'=>100000,'accepted_claim_replay_at_capacity'=>100000]as$case=>$rows){
 $directory=$root.'/'.$case;$store=new Store($directory);$provider=new OptoutCapacityProvider();$service=new Service($store,$provider,$root);
 if($case==='accepted_claim_replay_at_capacity'){$first=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),$now+900,$now);if($first['state']!=='accepted'||$provider->calls!==1){throw new RuntimeException('Replay positive initial submission failed.');}}
 if($rows){$db=new PDO('sqlite:'.$directory.'/deliveries.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$db->beginTransaction();$q=$db->prepare('INSERT INTO inbound_events(id,created_at)VALUES(?,?)');for($i=0;$i<$rows;$i++){$q->execute(['old_stop_'.$i,$now-1000]);}$db->commit();$db=null;}
 $callbackError='';$sendError='';$receipt=null;
 if(in_array($case,['signed_stop','unrecordable_signed_stop'],true)){
  $params=['MessageSid'=>'SM'.str_repeat('d',32),'AccountSid'=>'AC'.str_repeat('a',32),'MessageStatus'=>'received','From'=>'+15555550102','To'=>'+15555550101','Body'=>'STOP'];ksort($params,SORT_STRING);$signed=Service::callbackUrl($settings);foreach($params as$key=>$value){$signed.=$key.$value;}$signature=base64_encode(hash_hmac('sha1',$signed,$settings['announcement_sms']['twilio_auth_token'],true));
  try{$service->callback($settings,'',http_build_query($params,'','&',PHP_QUERY_RFC3986),['content-type'=>'application/x-www-form-urlencoded','x-twilio-signature'=>$signature],$now);}catch(RuntimeException$error){$callbackError=$error->getMessage();}
 }
 try{$receipt=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),$now+900,$now);}catch(DomainException|RuntimeException$error){$sendError=$error->getMessage();}
 $observed=['case'=>$case,'permanent_events_before'=>$rows,'callback_error'=>$callbackError,'provider_calls'=>$provider->calls,'send_error'=>$sendError,'receipt_state'=>$receipt['state']??null,'tombstones'=>$store->stats($now)['opt_outs']];echo'SLS_SMS_OPTOUT_CAPACITY '.json_encode($observed,JSON_THROW_ON_ERROR)."\n";
 $expected=in_array($case,['ordinary_send','near_capacity_send','accepted_claim_replay_at_capacity'],true)?1:0;if($provider->calls!==$expected){$failures[]=$case;}
 if($case==='signed_stop'&&($callbackError!==''||$sendError!=='sms_recipient_opted_out')){throw new RuntimeException('Signed STOP positive control did not follow actual consent path.');}
 if($case==='unrecordable_signed_stop'&&$callbackError!=='sms_opt_out_history_full'){throw new RuntimeException('Capacity boundary was not reached.');}
 if(in_array($case,['unrecordable_signed_stop','full_history_without_callback'],true)&&$provider->calls===0){if($sendError!=='sms_opt_out_history_full'||$store->stats($now)['periods']!==[]){throw new RuntimeException('Refused capacity admission created a reservation or wrong policy result.');}}
 if($case==='accepted_claim_replay_at_capacity'&&($receipt['state']!=='accepted'||$provider->calls!==1)){throw new RuntimeException('Full opt-out history corrupted or replayed prior accepted evidence.');}
}
if($failures){throw new RuntimeException('Outgoing provider reached after local STOP could not be recorded: '.implode(',',$failures));}
