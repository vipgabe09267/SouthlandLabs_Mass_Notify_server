<?php
declare(strict_types=1);
namespace SLS\MassNotify { function time(): int { return $GLOBALS['sls_email_clock']; } }
namespace FreePBX\modules { function time(): int { return $GLOBALS['sls_email_clock']; } }
namespace {
require dirname(__DIR__).'/slsmassnotifyserver/AnnouncementDelivery.php';
use SLS\MassNotify\ApiSecurity;
final class DeepEmailAuthority {
    use \FreePBX\modules\SlsAnnouncementDelivery;
    public array $settings = [], $sent = [], $outcomes = [];
    public bool $weather = true, $automation = true;
    private function getActiveSettings() { return $this->settings; }
    private function announcementEmailTargets($settings) { return !empty($settings['enabled']) ? $settings['targets'] : []; }
    private function announcementEmailFingerprint($target) { return hash('sha256',json_encode([$target['id'],$target['address'],$target['sender']['name'],$target['sender']['address']])); }
    private function automationContextPermitted($context) { return $this->automation; }
    private function weatherChannelAuthorization($context) { return ['status'=>$this->weather?'eligible':'cancelled']; }
    protected function submitAnnouncementEmail(array $envelope): array { $this->sent[]=$envelope; return array_shift($this->outcomes)?:['state'=>'accepted','retryable'=>false,'detail'=>'inert accepted']; }
    public function run(array $request, callable $duringIntent): array {
        $rows=[];
        (new ReflectionMethod(self::class,'deliverAnnouncementEmailTargets'))->invokeArgs($this,[$request,&$rows,function($receipts)use($duringIntent){
            if (($receipts[count($receipts)-1]['state']??'')==='submitting') { $duringIntent($this,$receipts); }
        }]);
        return $rows;
    }
    public function fingerprint(array $target): string { return $this->announcementEmailFingerprint($target); }
}
$failed=[]; $id='email_'.str_repeat('a',24); $base=1793184000;
foreach (['unchanged','revoke','expire','address','sender','disable','weather','automation','lifetime'] as $change) {
    $GLOBALS['sls_email_clock']=$base;
    $x=new DeepEmailAuthority();
    $target=['id'=>$id,'address'=>'private@example.com','sender'=>['name'=>'PBX','address'=>'notify@example.com']];
    $credential=ApiSecurity::issue(['name'=>'inert','scopes'=>['send'],'audience'=>['unrestricted'=>true],'expires_at'=>$base+5])['credential'];
    $x->settings=['enabled'=>true,'targets'=>[$id=>$target],'control_api'=>['enabled'=>'1','credentials'=>[$credential]]];
    $target['fingerprint']=$x->fingerprint($target); $target['message_id']='<sls-'.str_repeat('b',32).'-'.str_repeat('a',24).'@example.com>';
    $request=['email_recipient_ids'=>[$id],'email_targets'=>[$id=>$target],'email_attempt_id'=>'job_'.str_repeat('c',32),
        'email_expires_at'=>$base+5,'title'=>'inert','message'=>'private fixture only','delivery_timestamp'=>gmdate('c',$base)];
    if(in_array($change,['revoke','expire'],true))$request['api_credential_id']=$credential['id'];
    if($change==='weather')$request['weather_context']=['fixture'=>true];
    if($change==='automation')$request['automation_context']=['fixture'=>true];
    $rows=$x->run($request,function($x)use($change,$base,$id){
        if(in_array($change,['expire','lifetime'],true))$GLOBALS['sls_email_clock']=$base+10;
        elseif($change==='revoke')$x->settings['control_api']['credentials']=[];
        elseif($change==='address')$x->settings['targets'][$id]['address']='changed@example.com';
        elseif($change==='sender')$x->settings['targets'][$id]['sender']['address']='changed@example.com';
        elseif($change==='disable')$x->settings['enabled']=false;
        elseif($change==='weather')$x->weather=false;
        elseif($change==='automation')$x->automation=false;
    });
    $expected=$change==='unchanged'?1:0;
    $ok=count($x->sent)===$expected && ($change==='unchanged'||(($rows[0]['submission_started']??true)===false&&($rows[0]['retryable']??true)===false));
    echo json_encode(['case'=>$change,'inert_sender_calls'=>count($x->sent),'expected'=>$expected,'receipt_state'=>$rows[0]['state']??null,'submission_started'=>$rows[0]['submission_started']??null,'pass'=>$ok]),"\n";
    if(!$ok)$failed[]=$change;
}
foreach(['accepted','uncertain']as$firstState){
    $GLOBALS['sls_email_clock']=$base;$x=new DeepEmailAuthority();$other='email_'.str_repeat('b',24);
    $one=['id'=>$id,'address'=>'one@example.com','sender'=>['name'=>'PBX','address'=>'notify@example.com']];
    $two=['id'=>$other,'address'=>'two@example.com','sender'=>['name'=>'PBX','address'=>'notify@example.com']];
    $credential=ApiSecurity::issue(['name'=>'inert','scopes'=>['send'],'audience'=>['unrestricted'=>true]])['credential'];
    $x->settings=['enabled'=>true,'targets'=>[$id=>$one,$other=>$two],'control_api'=>['enabled'=>'1','credentials'=>[$credential]]];
    $targets=[];foreach([$id=>$one,$other=>$two]as$key=>$target){$target['fingerprint']=$x->fingerprint($target);$target['message_id']='<sls-'.str_repeat('c',32).'-'.substr($key,6).'@example.com>';$targets[$key]=$target;}
    $request=['email_recipient_ids'=>[$id,$other],'email_targets'=>$targets,'email_attempt_id'=>'job_'.str_repeat('d',32),
        'email_expires_at'=>$base+300,'title'=>'inert','message'=>'Private fixture only','delivery_timestamp'=>gmdate('c',$base),'api_credential_id'=>$credential['id']];
    $x->outcomes=[['state'=>$firstState,'retryable'=>false,'detail'=>'Original first effect evidence']];
    $rows=$x->run($request,function($x,$receipts){if(count($receipts)===2)$x->settings['control_api']['credentials']=[];});
    $ok=count($x->sent)===1&&$rows[0]['state']===$firstState&&$rows[0]['detail']==='Original first effect evidence'
        &&$rows[1]['state']==='cancelled'&&$rows[1]['submission_started']===false&&$rows[1]['retryable']===false;
    echo json_encode(['case'=>'retain_prior_'.$firstState,'inert_sender_calls'=>count($x->sent),'states'=>array_column($rows,'state'),'pass'=>$ok]),"\n";
    if(!$ok)$failed[]='retain_prior_'.$firstState;
}
if($failed)throw new RuntimeException('Late email authority failed: '.implode(', ',$failed));
}
