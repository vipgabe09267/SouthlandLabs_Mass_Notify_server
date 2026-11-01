<?php
declare(strict_types=1);
// Actual delivery trait, disposable job storage and inert channel adapters.
require __DIR__ . '/test_independent_channels.php';
class CredentialDeliveryFixture extends TestDelivery {
    public $settings=[];
    public function getActiveSettings(){return $this->settings;}
    public function getDeviceOverrideInventory(){return ['devices'=>[]];}
}
$issued=\SLS\MassNotify\ApiSecurity::issue(['name'=>'Restricted sender','scopes'=>['read','send'],
    'audience'=>['unrestricted'=>false,'extensions'=>['1000'],'desktop_client_ids'=>['device_gabe'],'webhook_ids'=>['hook']]]);
$principal=$issued['credential'];unset($principal['secret_hash']);
$fixture=new CredentialDeliveryFixture();$fixture->desktopFails=false;$fixture->audioFails=false;
$fixture->settings=['control_api'=>['enabled'=>true,'credentials'=>[$issued['credential']]],
    'desktop_clients'=>[['client_id'=>'device_gabe','username'=>'gabe','enabled'=>true]]];
$request['api_credential_id']=$principal['id'];$request['audio_mode']='none';
$request['desktop_client_ids']=['gabe'=>'device_gabe'];
$GLOBALS['sls_control_principal']=$principal;
$method=new ReflectionMethod(CredentialDeliveryFixture::class,'deliverResolvedAnnouncement');
$bad=$request;$bad['phones'][]='1001';
$denied=$method->invoke($fixture,$bad);
if(($denied['error_code']??'')!=='permission_denied'||$fixture->commands){throw new RuntimeException('Final resolved audience bypassed restricted credential.');}
$preview=$request;$preview['preview']=true;
$previewDirectory=sys_get_temp_dir().'/sls-api-preview-'.bin2hex(random_bytes(8));mkdir($previewDirectory,0700);
$fixture->jobDirectory=$previewDirectory;
try {
    $previewResult=$method->invoke($fixture,$preview);
    if(empty($previewResult['success'])||($previewResult['preview']??null)!==true){throw new RuntimeException('Authorized preview was rejected.');}
    if($fixture->commands||$fixture->notifyLogs||$fixture->audioPriority!==''||(glob($previewDirectory.'/*')?:[])){
        throw new RuntimeException('Authorized preview submitted a channel, recorded delivery, or queued work.');
    }
}finally{foreach(glob($previewDirectory.'/*')?:[] as $file)unlink($file);rmdir($previewDirectory);$fixture->jobDirectory='';}

// Legacy Control API jobs must retain a non-secret generation marker so a
// key rotation or disable takes effect after admission but before submission.
$legacyDirectory=sys_get_temp_dir().'/sls-api-legacy-'.bin2hex(random_bytes(8));mkdir($legacyDirectory,0700);
try {
    $legacyControl=['enabled'=>true,'api_key'=>'legacy-fixture-key-before-rotation'];
    $fixture->settings=['enabled'=>true,'control_api'=>$legacyControl,
        'desktop_clients'=>[['client_id'=>'device_gabe','username'=>'gabe','enabled'=>true]]];
    $legacy=\SLS\MassNotify\ApiSecurity::authenticate($legacyControl,$legacyControl['api_key']);
    $GLOBALS['sls_control_principal']=$legacy;$fixture->jobDirectory=$legacyDirectory;
    $queuedRequest=$request;unset($queuedRequest['api_credential_id']);$queuedRequest['force_queue']=true;
    $queued=$method->invoke($fixture,$queuedRequest);
    if(empty($queued['queued'])||!preg_match('/^job_[a-f0-9]{32}$/D',$queued['job_id']??'')){
        throw new RuntimeException('Legacy Control API announcement was not queued in the inert fixture.');
    }
    $stored=json_decode(file_get_contents($legacyDirectory.'/'.$queued['job_id'].'.json'),true,512,JSON_THROW_ON_ERROR)['request'];
    if(($stored['api_credential_id']??'')!=='legacy'
        ||($stored['api_credential_revision']??'')!==($legacy['authority_revision']??null)
        ||!preg_match('/^[a-f0-9]{64}$/D',$stored['api_credential_revision']??'')){
        throw new RuntimeException('Queued legacy authority did not retain its non-secret key generation.');
    }
    unset($GLOBALS['sls_control_principal']);
    $before=count($fixture->commands);$fixture->settings['control_api']['api_key']='legacy-fixture-key-after-rotation';
    $rotated=$fixture->run($stored);
    if(count($fixture->commands)!==$before||!$rotated['receipts']
        ||count(array_filter($rotated['receipts'],static fn($row)=>$row['state']==='cancelled'))!==count($rotated['receipts'])){
        throw new RuntimeException('Rotated legacy key retained queued delivery authority.');
    }
    $fixture->settings['control_api']=$legacyControl;$fixture->settings['control_api']['enabled']=false;
    $disabled=$fixture->run($stored);
    if(count($fixture->commands)!==$before||!$disabled['receipts']
        ||count(array_filter($disabled['receipts'],static fn($row)=>$row['state']==='cancelled'))!==count($disabled['receipts'])){
        throw new RuntimeException('Disabled legacy Control API retained queued delivery authority.');
    }
}finally{
    unset($GLOBALS['sls_control_principal']);
    foreach(glob($legacyDirectory.'/*')?:[] as $file)unlink($file);
    rmdir($legacyDirectory);$fixture->jobDirectory='';
}
unset($GLOBALS['sls_control_principal']);
$fixture->settings=['control_api'=>['enabled'=>true,'credentials'=>[$issued['credential']]],
    'desktop_clients'=>[['client_id'=>'device_gabe','username'=>'gabe','enabled'=>true]]];
$fixture->settings['control_api']['credentials'][0]['revoked_at']=gmdate('c');
$before=count($fixture->commands);$cancelled=$fixture->run($request);
if(count($fixture->commands)!==$before||count($cancelled['receipts'])!==3
    ||count(array_filter($cancelled['receipts'],static fn($row)=>$row['state']==='cancelled'))!==3){
    throw new RuntimeException('Revoked queued credential still submitted a channel.');
}
$fixture->settings['control_api']['credentials'][0]['revoked_at']='';
$fixture->audioPermissionDeniedTargets=['phones'=>['1000'],'voice_recipient_ids'=>[]];
$audioRequest=$request;$audioRequest['audio_mode']='tts';
$audioDenied=$fixture->run($audioRequest);
$deniedRows=array_values(array_filter($audioDenied['receipts'],static fn($row)=>$row['channel']==='audio'&&$row['target']==='1000'));
if(count($deniedRows)!==1||$deniedRows[0]['state']!=='cancelled'||$deniedRows[0]['retryable']){
    throw new RuntimeException('Audio recipients removed during speech preparation were reported as retryable failures.');
}
$fixture->audioPermissionDeniedTargets=['phones'=>[],'voice_recipient_ids'=>[]];
$fixture->settings['control_api']['credentials'][0]['audience']['extensions']=['1001'];
$fixture->currentTargets['phones']=['1000','1001'];
$partial=$fixture->run($request);
if(count(array_filter($partial['receipts'],static fn($row)=>$row['target']==='1001'))
    ||count(array_filter($partial['receipts'],static fn($row)=>$row['target']==='1000'&&$row['state']==='cancelled'))!==1){
    throw new RuntimeException('Changed permissions added new recipients or retained a removed recipient.');
}
$directory=sys_get_temp_dir().'/sls-api-jobs-'.bin2hex(random_bytes(8));mkdir($directory,0700);$fixture->jobDirectory=$directory;
$jobId='job_'.str_repeat('d',32);
try{
 $GLOBALS['sls_control_principal']=$principal;
 $job=['id'=>$jobId,'state'=>'queued','created_at'=>gmdate('c'),'request'=>$request,'receipts'=>[],'message'=>'fixture'];
 file_put_contents($directory.'/'.$jobId.'.json',json_encode($job));
 if(($fixture->getAnnouncementJob($jobId)['api_credential_id']??'')!==$principal['id'])throw new RuntimeException('Own job read failed.');
 $GLOBALS['sls_control_principal']['id']='api_'.str_repeat('e',24);
 foreach([$fixture->getAnnouncementJob($jobId),$fixture->retryFailedAnnouncementJob($jobId)] as $result){
   if(($result['error_code']??'')!=='permission_denied')throw new RuntimeException('Another key could read or retry a restricted job.');
 }
	 $foreignId='job_'.str_repeat('c',32);$old=gmdate('c',time()-90);
	 $foreign=['id'=>$foreignId,'state'=>'queued','created_at'=>$old,'startup_attempted_at'=>$old,'request'=>$request,'receipts'=>[],'message'=>'fixture'];
	 $foreignPath=$directory.'/'.$foreignId.'.json';file_put_contents($foreignPath,json_encode($foreign));$beforeForeign=file_get_contents($foreignPath);
	 $foreignResult=$fixture->getAnnouncementJob($foreignId);
	 if(($foreignResult['error_code']??'')!=='permission_denied'||file_get_contents($foreignPath)!==$beforeForeign||file_exists($foreignPath.'.lock')){
	   throw new RuntimeException('Unauthorized job polling reconciled or mutated another credential\'s queued work.');
	 }
}finally{unset($GLOBALS['sls_control_principal']);foreach(glob($directory.'/*')?:[] as $file)unlink($file);rmdir($directory);}
echo "Resolved API audiences, queued revocation, recipient intersection and job ownership passed.\n";
