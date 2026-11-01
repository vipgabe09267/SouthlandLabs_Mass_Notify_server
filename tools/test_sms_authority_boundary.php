<?php
declare(strict_types=1);
namespace SLS\MassNotify { function time(): int { return $GLOBALS['sls_authority_clock']; } }
namespace FreePBX\modules { function time(): int { return $GLOBALS['sls_authority_clock']; } }
namespace SLS\MassNotify\Sms {
    function fsync($handle): bool {
        if (($GLOBALS['sls_authority_publication_advance']??false)===true) {
            $GLOBALS['sls_authority_publication_advance']=false;$GLOBALS['sls_authority_clock']+=10;
        }
        return \fsync($handle);
    }
}
namespace {
if (getenv('SLS_TEST_NAMESPACE') !== 'entered') { throw new RuntimeException('Use the unchanged isolated wrapper.'); }
require dirname(__DIR__).'/slsmassnotifyserver/AnnouncementSms.php';
require dirname(__DIR__).'/slsmassnotifyserver/EnterpriseClusterIntegration.php';
require dirname(__DIR__).'/slsmassnotifyserver/api/sls-mass-notify/security.php';
use SLS\MassNotify\ApiSecurity;
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
final class AuthorityRecordingProvider extends Provider {
    public array $calls=[];
    protected function request(string $url,array $headers,string $body,?string $basic): array {
        $this->calls[]=['at'=>$GLOBALS['sls_authority_clock']];
        return ['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'SM'.str_repeat('b',32),
            'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];
    }
}
final class AuthoritySmsModule {
    use \FreePBX\modules\SlsAnnouncementSms;
    public array $settings=[];
    public Service $service;
    public bool $weatherAllowed=true;
    public bool $automationAllowed=true;
    public bool $failSettings=false;
    public string $lateAuthorityChange='';
    public int $weatherCalls=0;
    public int $automationCalls=0;
    public function getActiveSettings(): array { if ($this->failSettings) { throw new RuntimeException('Synthetic protected settings read failure'); } return $this->settings; }
    protected function announcementSmsService(): Service { return $this->service; }
    private function scheduledAnnouncementDeadline(array $request): ?int { return null; }
    private function weatherChannelAuthorization(array $context): array {
        if (++$this->weatherCalls===2) {
            if ($this->lateAuthorityChange==='weather_expiry') { $GLOBALS['sls_authority_clock']+=10; }
            if ($this->lateAuthorityChange==='weather_revocation') { $this->settings['control_api']['credentials'][0]['revoked_at']=gmdate('c'); }
        }
        return ['status'=>$this->weatherAllowed?'eligible':'cancelled','sms_recipient_ids'=>['sms_'.str_repeat('a',24)]];
    }
    private function automationContextPermitted(array $context): bool {
        if (++$this->automationCalls===2 && $this->lateAuthorityChange==='automation_expiry') { $GLOBALS['sls_authority_clock']+=10; }
        return $this->automationAllowed;
    }
    public function run(array $request,callable $progress): array {
        $receipts=[];$this->deliverAnnouncementSmsTargets($request,$receipts,$progress);return $receipts;
    }
}
$root=sys_get_temp_dir().'/sls-sms-authority-'.bin2hex(random_bytes(8));mkdir($root,0700);
$id='sms_'.str_repeat('a',24);$base=1793178000;$failures=[];
try {
    foreach (['unchanged'=>0,'expiry_during_progress'=>10,'revocation_during_progress'=>0,
        'runtime_paused_during_progress'=>0,'weather_cancelled_during_progress'=>0,
        'automation_cancelled_during_progress'=>0,'api_scope_removed_during_progress'=>0,
        'api_audience_removed_during_progress'=>0,'settings_unavailable_after_progress'=>0,
        'expiry_during_final_weather_authorization'=>0,'revocation_during_final_weather_authorization'=>0,
        'expiry_during_final_automation_authorization'=>0,
        'expiry_during_publication'=>0] as $name=>$advance) {
        $GLOBALS['sls_authority_clock']=$base;
        $issued=ApiSecurity::issue(['name'=>'Synthetic restricted sender','scopes'=>['send'],'expires_at'=>$base+5,
            'audience'=>['unrestricted'=>false,'sms_recipient_ids'=>[$id]]]);
        $settings=['runtime_enabled'=>true,'public_pbx_host'=>'pbx.example.invalid',
            'control_api'=>['enabled'=>true,'base_url'=>'https://pbx.example.invalid/api/sls-mass-notify',
                'credentials'=>[$issued['credential']]],
            'announcement_sms'=>Config::normalize(['enabled'=>true,'provider'=>'twilio','message_format'=>'sms',
                'from'=>'+15555550101','organization'=>'SLS','segment_cost_micros'=>10000,'twilio_account_sid'=>'AC'.str_repeat('a',32),
                'twilio_key_sid'=>'SK'.str_repeat('b',32),'twilio_key_secret'=>'synthetic-key','twilio_auth_token'=>str_repeat('c',32),
                'recipients'=>[['id'=>$id,'name'=>'Synthetic recipient','number'=>'+15555550102','enabled'=>true,
                    'consent'=>true,'consent_note'=>'Private fixture only','consent_at'=>gmdate('c',$base-3600)]]])];
        $media=[];$data='';
        if ($name==='expiry_during_publication') {
            $settings['announcement_sms']['message_format']='mms';$settings['announcement_sms']['mms_cost_micros']=10000;
            $data=base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZQmcAAAAASUVORK5CYII=',true);
            $media=['url'=>'https://pbx.example.invalid/sls_mass_notify/mms_20261028000000_'.str_repeat('f',32).'.png','sha256'=>hash('sha256',$data),'bytes'=>strlen($data)];
            $settings['announcement_sms']=Config::normalize($settings['announcement_sms']);
        }
        $module=new AuthoritySmsModule();$module->settings=$settings;
        $provider=new AuthorityRecordingProvider();$store=new Store($root.'/'.$name);$module->service=new Service($store,$provider,$root);
        $request=['api_credential_id'=>$issued['credential']['id'],'sms_recipient_ids'=>[$id],
            'sms_targets'=>Service::snapshot($settings,[$id],'Fixture','Synthetic authority observation',false,$media),
            'delivery_id'=>'announcement-'.str_repeat('d',32),'sms_attempt_id'=>'job_'.str_repeat('e',32),'sms_expires_at'=>$base+900];
        if ($data!=='') { $request['sms_media']=['data'=>base64_encode($data)]; }
        if ($name==='weather_cancelled_during_progress') { $request['weather_context']=['synthetic'=>true]; }
        if ($name==='automation_cancelled_during_progress') { $request['automation_context']=['synthetic'=>true]; }
        if ($name==='expiry_during_final_weather_authorization' || $name==='revocation_during_final_weather_authorization') {
            $request['weather_context']=['synthetic'=>true];$module->lateAuthorityChange=$name[0]==='e'?'weather_expiry':'weather_revocation';
        }
        if ($name==='expiry_during_final_automation_authorization') {
            $request['automation_context']=['synthetic'=>true];$module->lateAuthorityChange='automation_expiry';
        }
        $GLOBALS['sls_authority_publication_advance']=$name==='expiry_during_publication';
        $changed=false;
        $receipts=$module->run($request,static function()use(&$changed,$advance,$module,$name):void {
            if ($changed) { return; }$changed=true;$GLOBALS['sls_authority_clock']+=$advance;
            if ($name==='revocation_during_progress') { $module->settings['control_api']['credentials'][0]['revoked_at']=gmdate('c'); }
            if ($name==='runtime_paused_during_progress') { $module->settings['runtime_enabled']=false; }
            if ($name==='weather_cancelled_during_progress') { $module->weatherAllowed=false; }
            if ($name==='automation_cancelled_during_progress') { $module->automationAllowed=false; }
            if ($name==='api_scope_removed_during_progress') { $module->settings['control_api']['credentials'][0]['scopes']=['read']; }
            if ($name==='api_audience_removed_during_progress') { $module->settings['control_api']['credentials'][0]['audience']['sms_recipient_ids']=[]; }
            if ($name==='settings_unavailable_after_progress') { $module->failSettings=true; }
        });
        echo 'SLS_SMS_AUTHORITY '.json_encode(['case'=>$name,'credential_expires_at'=>$base+5,
            'current_credential'=>ApiSecurity::currentCredential($module->settings,$issued['credential']['id'])!==null,
            'provider_calls'=>$provider->calls,'receipts'=>$receipts],JSON_THROW_ON_ERROR)."\n";
        $expected=$name==='unchanged'?1:0;
        if (count($provider->calls)!==$expected) { $failures[]=$name.' submitted after authority changed'; }
        if ($expected===0 && count($provider->calls)===0) {
            if ($receipts[0]['state']!=='cancelled' || $receipts[0]['submission_started']!==false) { throw new RuntimeException('Known suppression was not projected as an unsubmitted cancellation.'); }
            $callbackReached=false;
            $replay=$module->service->send($settings,$request['sms_targets'][$id],$request['delivery_id'],$request['sms_attempt_id'],$request['sms_expires_at'],$base,
                $request['sms_media']['data']??'',static function()use(&$callbackReached):bool { $callbackReached=true;return true; });
            if ($callbackReached || $replay['state']!=='cancelled' || $provider->calls) { throw new RuntimeException('Consumed cancelled claim was reopened on repetition.'); }
            foreach ($store->stats($base)['periods'] as $period) {
                if ((int)$period['segments']!==1 || (int)$period['amount']!==10000) { throw new RuntimeException('Suppression duplicated or released the original budget reservation.'); }
            }
        }
    }
    if ($failures) { throw new RuntimeException(implode('; ',$failures)); }
} finally {
    $files=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) { $file->isDir()?rmdir($file->getPathname()):unlink($file->getPathname()); }rmdir($root);
}
}
