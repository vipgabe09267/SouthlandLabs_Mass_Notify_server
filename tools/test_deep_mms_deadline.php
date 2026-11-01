<?php
declare(strict_types=1);
namespace SLS\MassNotify\Sms {
    function fsync($handle): bool {
        if (($GLOBALS['sls_mms_delay_once'] ?? false) === true) {
            $GLOBALS['sls_mms_delay_once'] = false;
            usleep(7000000);
        }
        return \fsync($handle);
    }
}
namespace {
if (getenv('SLS_TEST_NAMESPACE') !== 'entered') { throw new \RuntimeException('Use the unchanged isolated test wrapper.'); }
require dirname(__DIR__).'/slsmassnotifyserver/api/sls-mass-notify/sms/Service.php';
use SLS\MassNotify\Sms\{Config,Provider,Service,Store};
final class DeadlineFixtureProvider extends Provider
{
    public array $requests=[];
    protected function request(string $url,array $headers,string $body,?string $basic): array {
        $this->requests[]=['sent_at'=>time()];
        return ['status'=>201,'error'=>0,'body'=>json_encode(['sid'=>'MM'.str_repeat('b',32),
            'account_sid'=>'AC'.str_repeat('a',32),'from'=>'+15555550101','to'=>'+15555550102'],JSON_THROW_ON_ERROR)];
    }
}
$root=sys_get_temp_dir().'/sls-mms-deadline-'.bin2hex(random_bytes(8));
if (!mkdir($root,0700)) { throw new \RuntimeException('Unable to create private fixture directory.'); }
try {
    foreach (['unchanged'=>900,'expired_during_publication'=>6] as $name=>$lifetime) {
        $now=time();$recipient='sms_'.str_repeat('a',24);
        $config=Config::normalize(['enabled'=>true,'provider'=>'twilio','message_format'=>'mms',
            'mms_cost_micros'=>10000,'from'=>'+15555550101','organization'=>'SLS',
            'twilio_account_sid'=>'AC'.str_repeat('a',32),'twilio_key_sid'=>'SK'.str_repeat('b',32),
            'twilio_key_secret'=>'synthetic-key','twilio_auth_token'=>str_repeat('c',32),
            'recipients'=>[['id'=>$recipient,'name'=>'Synthetic recipient','number'=>'+15555550102',
                'enabled'=>true,'consent'=>true,'consent_note'=>'Private fixture only','consent_at'=>gmdate('c',$now-3600)]]]);
        $settings=['announcement_sms'=>$config,'public_pbx_host'=>'pbx.example.invalid',
            'control_api'=>['base_url'=>'https://pbx.example.invalid/api/sls-mass-notify']];
        $image=base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZQmcAAAAASUVORK5CYII=',true);
        $media=['url'=>'https://pbx.example.invalid/sls_mass_notify/mms_20261028000000_'.str_repeat('d',32).'.png',
            'sha256'=>hash('sha256',$image),'bytes'=>strlen($image)];
        $frozen=Service::snapshot($settings,[$recipient],'Fixture','Synthetic deadline evidence',false,$media)[$recipient];
        $directory=$root.'/'.$name;mkdir($directory,0700);$public=$directory.'/public';mkdir($public,0750);
        $store=new Store($directory.'/ledger');$provider=new DeadlineFixtureProvider();$service=new Service($store,$provider,$public);
        $GLOBALS['sls_mms_delay_once']=$lifetime===6;
        $receipt=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),
            $now+$lifetime,$now,base64_encode($image));
        echo 'SLS_MMS_DEADLINE '.json_encode(['case'=>$name,'entered_at'=>$now,'expires_at'=>$now+$lifetime,
            'returned_at'=>time(),'recording_transport_calls'=>$provider->requests,'state'=>$receipt['state'],
            'submission_started'=>$receipt['submission_started']],JSON_THROW_ON_ERROR)."\n";
        if ($lifetime===900 && (count($provider->requests)!==1 || $receipt['state']!=='accepted')) {
            throw new \RuntimeException('Unchanged positive MMS path did not submit one accepted message.');
        }
        if ($lifetime===6 && (count($provider->requests)!==0 || $receipt['state']!=='failed' || $receipt['submission_started']!==false)) {
            throw new \RuntimeException('MMS provider submission started after storage consumed its original deadline.');
        }
        if ($lifetime===6) {
            $repeated=$service->send($settings,$frozen,'announcement-'.str_repeat('e',32),'job_'.str_repeat('f',32),
                $now+$lifetime,$now,base64_encode($image));
            if ($repeated['state']!=='failed' || count($provider->requests)!==0) {
                throw new \RuntimeException('A consumed expired claim was reopened or submitted on repetition.');
            }
            foreach($store->stats($now)['periods'] as $period){
                if((int)$period['segments']!==1 || (int)$period['amount']!==10000){
                    throw new \RuntimeException('Deadline refusal reset or duplicated the original conservative budget reservation.');
                }
            }
        }
    }
} finally {
    $files=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);
    foreach($files as $file){if($file->isDir()){rmdir($file->getPathname());}else{unlink($file->getPathname());}}
    rmdir($root);
}
}
