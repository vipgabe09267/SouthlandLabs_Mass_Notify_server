<?php
/** Private composition probe: actual authorizer + real bounded SQLite wait. */
declare(strict_types=1);
if(getenv('SLS_TEST_NAMESPACE')!=='entered'){throw new RuntimeException('Use isolated wrapper.');}
$source=dirname(__DIR__); // The unchanged wrapper supplies the private source tree.
require $source.'/slsmassnotifyserver/AnnouncementSms.php';
require $source.'/slsmassnotifyserver/EnterpriseClusterIntegration.php';
use SLS\MassNotify\ApiSecurity;
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
class ConsentWaitProvider extends Provider {
 public array $calls=[];public $owner;
 protected function request(string $url,array $headers,string $body,?string $basic):array {
  $principal=ApiSecurity::currentCredential($this->owner->settings,$this->owner->credential);
  $this->calls[]=['at'=>microtime(true),'principal_active'=>$principal!==null];
  return ['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'SM'.str_repeat('b',32),'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];
 }
}
class ConsentWaitModule {
 use \FreePBX\modules\SlsAnnouncementSms { announcementSmsSubmissionPermitted as private actualSubmissionPermitted; }
 public array $settings=[];public Service $service;public string $directory,$credential,$mode;public bool $armed=false;
 public $writer=null;public array $writerPipes=[];public float $authorizedAt=0,$authorizationReturnedAt=0,$returnedAt=0;public bool $authorizationWasCurrent=false;public array $writerObservation=[];
 private function announcementSmsSubmissionPermitted(array $request,string $id,int $started) {
  $result=$this->actualSubmissionPermitted($request,$id,$started);
  $this->authorizationWasCurrent=$result===true||(is_array($result)&&($result['allowed']??null)===true);
  $this->authorizationReturnedAt=microtime(true);
  return$result;
 }
 protected function announcementSmsService():Service{return $this->service;}
 private function scheduledAnnouncementDeadline(array $request):?int{return null;}
 public function getActiveSettings():array {
  $final=false;foreach(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)as$frame){if(($frame['class']??'')===Service::class&&($frame['function']??'')==='send'){$final=true;break;}}
  if($final&&!$this->armed){
   $this->armed=true;
   if($this->mode==='sqlite_wait'){
    // Enter the last authorization shortly before a real UTC-second expiry.
    $now=microtime(true);$phase=floor($now)+.92;if($phase<$now){$phase+=1;}usleep((int)(($phase-$now)*1e6));
    $this->settings['control_api']['credentials'][0]['expires_at']=time()+1;
    $program='$db=new PDO("sqlite:".$argv[1]);$db->exec("BEGIN EXCLUSIVE");$start=microtime(true);fwrite(STDOUT,"ready\\n");fflush(STDOUT);usleep(180000);$db->exec("COMMIT");file_put_contents($argv[2],json_encode(["locked_at"=>$start,"released_at"=>microtime(true)]));';
    $this->writer=proc_open(['/usr/bin/php','-r',$program,$this->directory.'/deliveries.sqlite',$this->directory.'/writer-observation.json'],[0=>['pipe','r'],1=>['pipe','w'],2=>['file','/dev/null','w']],$this->writerPipes,'/',[],['bypass_shell'=>true]);
    if(!is_resource($this->writer)){throw new RuntimeException('Private SQLite writer did not start.');}
    fclose($this->writerPipes[0]);unset($this->writerPipes[0]);stream_set_timeout($this->writerPipes[1],2);
    if(fgets($this->writerPipes[1])!=="ready\n"){throw new RuntimeException('Private SQLite writer did not acquire lock.');}
   }
   $this->authorizedAt=microtime(true);
   if(ApiSecurity::currentCredential($this->settings,$this->credential)===null){throw new RuntimeException('Probe did not enter final authorization before expiry.');}
  }
  return $this->settings;
 }
 public function run(array $request):array{$rows=[];$this->deliverAnnouncementSmsTargets($request,$rows,static function(){});return$rows;}
 public function finishWriter():void {
  foreach($this->writerPipes as$pipe){if(is_resource($pipe)){fclose($pipe);}}$this->writerPipes=[];
  if(is_resource($this->writer)){$status=proc_get_status($this->writer);if($status['running']){proc_terminate($this->writer);}$code=proc_close($this->writer);$this->writer=null;}
  if(is_file($this->directory.'/writer-observation.json')){$this->writerObservation=json_decode(file_get_contents($this->directory.'/writer-observation.json'),true,8,JSON_THROW_ON_ERROR);}
 }
}
$root=sys_get_temp_dir().'/sls-consent-authority-wait-'.bin2hex(random_bytes(8));mkdir($root,0700);$failures=[];
try{
 foreach(['ordinary','sqlite_wait']as$mode){
  $module=new ConsentWaitModule();$module->mode=$mode;$module->directory=$root.'/'.$mode;
  $id='sms_'.str_repeat('a',24);$issued=ApiSecurity::issue(['name'=>'Private source','scopes'=>['send'],'audience'=>['unrestricted'=>true],'expires_at'=>time()+60]);$module->credential=$issued['credential']['id'];
  $module->settings=['runtime_enabled'=>true,'public_pbx_host'=>'pbx.example.invalid','control_api'=>['enabled'=>true,'base_url'=>'https://pbx.example.invalid/api/sls-mass-notify','credentials'=>[$issued['credential']]],
   'announcement_sms'=>Config::normalize(['enabled'=>true,'provider'=>'twilio','message_format'=>'sms','from'=>'+15555550101','organization'=>'SLS','segment_cost_micros'=>10000,'twilio_account_sid'=>'AC'.str_repeat('a',32),'twilio_key_sid'=>'SK'.str_repeat('b',32),'twilio_key_secret'=>'inert','twilio_auth_token'=>str_repeat('c',32),'recipients'=>[['id'=>$id,'name'=>'Private target','number'=>'+15555550102','enabled'=>true,'consent'=>true,'consent_note'=>'Synthetic','consent_at'=>gmdate('c',time()-3600)]]])];
  $provider=new ConsentWaitProvider();$provider->owner=$module;$store=new Store($module->directory);$module->service=new Service($store,$provider,$root);
  $request=['api_credential_id'=>$module->credential,'sms_recipient_ids'=>[$id],'sms_targets'=>Service::snapshot($module->settings,[$id],'Inert','No provider traffic.',false),'delivery_id'=>'announcement-'.str_repeat('d',32),'sms_attempt_id'=>'job_'.str_repeat('e',32),'sms_expires_at'=>time()+900];
  try{$rows=$module->run($request);$module->returnedAt=microtime(true);}finally{$module->finishWriter();}
  $expires=$module->settings['control_api']['credentials'][0]['expires_at'];
  $validSetup=$module->armed&&$module->authorizationWasCurrent&&$module->authorizationReturnedAt<$expires;
  if($mode==='sqlite_wait'){$validSetup=$validSetup&&($module->writerObservation['released_at']??0)>$module->authorizationReturnedAt&&($module->writerObservation['released_at']-$module->writerObservation['locked_at'])>=.15&&$module->returnedAt-$module->authorizationReturnedAt>=.15;}
  $observed=['case'=>$mode,'last_authorization_at'=>$module->authorizedAt,'authorization_returned_at'=>$module->authorizationReturnedAt,'authorization_was_current'=>$module->authorizationWasCurrent,'principal_expires_at'=>$expires,'writer'=>$module->writerObservation,'service_returned_at'=>$module->returnedAt,'valid_setup'=>$validSetup,'provider_calls'=>$provider->calls,'receipt_state'=>$rows[0]['state']??null,'submission_started'=>$rows[0]['submission_started']??null];echo'SLS_CONSENT_AUTHORITY_WAIT '.json_encode($observed,JSON_THROW_ON_ERROR)."\n";
  if(!$validSetup){throw new RuntimeException('Writer probe did not prove a current authorizer followed by an actual pending writer interval.');}
  $expectEarlierSubmission=getenv('SLS_SMS_EXPECT_BEFORE_CONSENT')==='1';
  $correct=$mode==='ordinary'||$expectEarlierSubmission?count($provider->calls)===1&&$provider->calls[0]['principal_active']:count($provider->calls)===0&&($rows[0]['submission_started']??true)===false;
  if(!$correct){$failures[]=$mode;}
 }
 if($failures){throw new RuntimeException('SQLite consent preparation outlived actor authorization: '.implode(',',$failures));}
}finally{
 $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$p){$p->isDir()?rmdir((string)$p):unlink((string)$p);}rmdir($root);
}
