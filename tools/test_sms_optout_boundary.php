<?php
declare(strict_types=1);
namespace SLS\MassNotify\Sms {
 function fsync($handle):bool {
  $ok=\fsync($handle); $callback=$GLOBALS['sls_optout_during_publish']??null;
  if(is_callable($callback)){ $GLOBALS['sls_optout_during_publish']=null;$callback(); }
  return $ok;
 }
}
namespace {
if(getenv('SLS_TEST_NAMESPACE')!=='entered'){throw new \RuntimeException('Use isolated wrapper.');}
require dirname(__DIR__).'/slsmassnotifyserver/api/sls-mass-notify/sms/Service.php';
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
final class OptoutBoundaryProvider extends Provider {
 public int $calls=0;
 protected function request(string $url,array $headers,string $body,?string $basic):array {
  $this->calls++;return['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'MM'.str_repeat('b',32),'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];
 }
}
function stop(Service $service,array $settings,int $now):void {
 $params=['MessageSid'=>'SM'.str_repeat('d',32),'AccountSid'=>'AC'.str_repeat('a',32),'MessageStatus'=>'received','From'=>'+15555550102','To'=>'+15555550101','Body'=>'STOP'];ksort($params,SORT_STRING);$signed=Service::callbackUrl($settings);foreach($params as$key=>$value){$signed.=$key.$value;}
 $signature=base64_encode(hash_hmac('sha1',$signed,$settings['announcement_sms']['twilio_auth_token'],true));
 $service->callback($settings,'',http_build_query($params,'','&',PHP_QUERY_RFC3986),['content-type'=>'application/x-www-form-urlencoded','x-twilio-signature'=>$signature],$now);
}
$root=sys_get_temp_dir().'/sls-optout-boundary-'.bin2hex(random_bytes(8));mkdir($root,0700);$failures=[];
try {
 foreach(['ordinary_mms','stop_before_claim','stop_during_publication','new_consent_after_stop','replayed_stop_after_new_consent','capacity_fills_during_publication']as$case){
  $now=time();$id='sms_'.str_repeat('a',24);$config=Config::normalize(['enabled'=>true,'provider'=>'twilio','message_format'=>'mms','mms_cost_micros'=>10000,'from'=>'+15555550101','organization'=>'SLS','twilio_account_sid'=>'AC'.str_repeat('a',32),'twilio_key_sid'=>'SK'.str_repeat('b',32),'twilio_key_secret'=>'synthetic','twilio_auth_token'=>str_repeat('c',32),'recipients'=>[['id'=>$id,'name'=>'Private recipient','number'=>'+15555550102','enabled'=>true,'consent'=>true,'consent_note'=>'Fixture','consent_at'=>gmdate('c',$now-3600)]]]);
  $settings=['announcement_sms'=>$config,'public_pbx_host'=>'pbx.example.invalid','control_api'=>['base_url'=>'https://pbx.example.invalid/api/sls-mass-notify']];
  $folder=$root.'/'.$case;mkdir($folder,0700);mkdir($folder.'/public',0750);$store=new Store($folder.'/ledger');$provider=new OptoutBoundaryProvider();$service=new Service($store,$provider,$folder.'/public');
  if(in_array($case,['stop_before_claim','new_consent_after_stop','replayed_stop_after_new_consent'],true)){stop($service,$settings,$now-10);}
  if(in_array($case,['new_consent_after_stop','replayed_stop_after_new_consent'],true)){$settings['announcement_sms']['recipients'][0]['consent_at']=gmdate('c',$now-5);}
  if($case==='replayed_stop_after_new_consent'){stop($service,$settings,$now);}
  $image=base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZQmcAAAAASUVORK5CYII=',true);$media=['url'=>'https://pbx.example.invalid/sls_mass_notify/mms_20261028000000_'.str_repeat('d',32).'.png','sha256'=>hash('sha256',$image),'bytes'=>strlen($image)];$frozen=Service::snapshot($settings,[$id],'Fixture','No real provider.',false,$media)[$id];
  if($case==='capacity_fills_during_publication'){$db=new PDO('sqlite:'.$folder.'/ledger/deliveries.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$db->beginTransaction();$q=$db->prepare('INSERT INTO inbound_events VALUES(?,?)');for($i=0;$i<99999;$i++){$q->execute(['prior_'.$i,$now-10]);}$db->commit();$db=null;}
  $GLOBALS['sls_optout_during_publish']=$case==='stop_during_publication'?static fn()=>stop($service,$settings,$now):($case==='capacity_fills_during_publication'?static fn()=>$store->optOut('last_capacity_event',hash('sha256','+15555550999'),$now):null);$receipt=null;$error='';
  try{$receipt=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),$now+900,$now,base64_encode($image));}catch(\DomainException$e){$error=$e->getMessage();}
  $shouldSend=in_array($case,['ordinary_mms','new_consent_after_stop','replayed_stop_after_new_consent'],true);$expected=$shouldSend?1:0;
  echo'SLS_SMS_OPTOUT_BOUNDARY '.json_encode(['case'=>$case,'calls'=>$provider->calls,'state'=>$receipt['state']??null,'submission_started'=>$receipt['submission_started']??null,'error'=>$error,'opt_outs'=>$store->stats($now)['opt_outs']],JSON_THROW_ON_ERROR)."\n";
  if($provider->calls!==$expected){$failures[]=$case;}
  if(in_array($case,['stop_during_publication','capacity_fills_during_publication'],true)&&$provider->calls===0){
   if($receipt['submission_started']!==false||$receipt['state']!=='cancelled'){throw new \RuntimeException('Known STOP refusal was mislabeled as a provider submission.');}
   $repeat=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),$now+900,$now,base64_encode($image));
   if($repeat['state']!=='cancelled'||$provider->calls!==0){throw new \RuntimeException('Consumed STOP-suppressed claim reopened.');}
   foreach($store->stats($now)['periods']as$period){if((int)$period['segments']!==1||(int)$period['amount']!==10000){throw new \RuntimeException('Consumed reservation changed.');}}
  }
 }
 if($failures){throw new \RuntimeException('Provider invoked despite already committed local STOP: '.implode(',',$failures));}
}finally{
 $it=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($root);
}
}
