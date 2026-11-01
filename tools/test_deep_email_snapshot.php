<?php
declare(strict_types=1);
namespace FreePBX\modules {
    function fopen($path, $mode, ...$arguments) {
        $handle=\fopen($path,$mode,...$arguments);
        if (is_resource($handle) && is_callable($GLOBALS['sls_email_snapshot_race']??null)) {
            foreach(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
                if (($frame['function']??'')==='announcementEmailAuthorizationHashes') {
                    $callback=$GLOBALS['sls_email_snapshot_race'];$GLOBALS['sls_email_snapshot_race']=null;$callback();break;
                }
            }
        }
        return $handle;
    }
}
namespace {
if(!interface_exists('BMO')){interface BMO{}}
require_once dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
require_once dirname(__DIR__).'/slsmassnotifyserver/DeliveryAuthorization.php';
use SLS\MassNotify\DeliveryAuthorization as Policy;
$root=sys_get_temp_dir().'/sls-email-snapshot-'.bin2hex(random_bytes(8));mkdir($root,0700);
$class=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);$source=file($class->getFileName());
$extract=static function(string $name)use($class):string{$method=$class->getMethod($name);return implode('',array_slice(file($method->getFileName()),$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));};
$methods='';
foreach(['getActiveSettings','loadSettingsFile','settingsCacheFingerprint','configurationPathMetadata','announcementEmailAuthorizationHashes','normalizeEmailSenderDomain','normalizeEmailSenderLocalPart'] as $name){$methods.=$extract($name)."\n";}
// The actual method's dependency is already loaded; eval has a different __DIR__.
$methods=str_replace("require_once __DIR__ . '/DeliveryAuthorization.php';",'', $methods);
$main=implode('',$source);$start=strpos($main,'$mailFromName = trim(preg_replace(');$end=strpos($main,"\$settings['alert_email_subject'] =",$start);
if($start===false||$end===false)throw new RuntimeException('Actual sender normalization block unavailable.');
$sender=substr($main,$start,$end-$start);
$body='namespace FreePBX\\modules; final class DeepEmailSnapshotFixture { use SlsAnnouncementEmail;'
    .'const SETTINGS_JSON='.var_export($root.'/settings.config',true).';const LEGACY_SETTINGS_JSON='.var_export($root.'/legacy.config',true).';const LEGACY_OLD_SETTINGS_JSON='.var_export($root.'/old.config',true).';const DEFAULT_NWS_OPENING_TONE="";'
    .'private $normalizedSettingsCache=[];private function rememberSettingsFingerprint($path){}'
    .'private function getDefaultSettings(){return ["mail_from_name"=>"SLS Mass Notification System","mail_from_local_part"=>"no-reply","mail_from_domain"=>"fixture.example.com","mail_from_addr"=>"no-reply@fixture.example.com","mail_to"=>""];}'
    .'private function normalizeSettings(array $settings){'.$sender.'$settings["announcement_email"]=$this->normalizeAnnouncementEmail($settings["announcement_email"]??[]);return $settings;}'
    .'public function settings(){return $this->getActiveSettings();}public function target($id){return $this->announcementEmailTargets($this->getActiveSettings())[$id];}'
    .'public function fingerprint($target){return $this->announcementEmailFingerprint($target);}public function capture($id,$hash){return $this->announcementEmailAuthorizationHashes($id,$hash);}public function defaulted(){return $this->loadSettingsFile(self::SETTINGS_JSON);}'
    .$methods.'}';
eval($body);
$id='email_'.str_repeat('a',24);$checks=0;
$check=static function($ok,$detail)use(&$checks){$checks++;if(!$ok)throw new RuntimeException($detail);};
$write=static function(array $settings)use($root){$temp=$root.'/new.config';file_put_contents($temp,json_encode($settings,JSON_THROW_ON_ERROR));chmod($temp,0600);rename($temp,$root.'/settings.config');};
try {
    $base=['announcement_email'=>['enabled'=>'1','recipients'=>[['id'=>$id,'name'=>'Private fixture','address'=>'private@example.com','enabled'=>'1']]],
        'mail_from_name'=>'PBX','mail_from_domain'=>'example.com','mail_from_local_part'=>'notify'];
    $cases=['canonical'=>$base];
    $legacy=$base;unset($legacy['mail_from_domain'],$legacy['mail_from_local_part']);$legacy['mail_from_addr']='legacy@example.com';$cases['legacy_address']=$legacy;
    $defaults=$base;unset($defaults['mail_from_name'],$defaults['mail_from_local_part'],$defaults['announcement_email']['recipients'][0]['enabled']);$cases['default_name_localpart_and_flag']=$defaults;
    $normalized=$base;$normalized['mail_from_name']='  '.str_repeat('Long name ',12)."\x01  ";$normalized['mail_from_domain']='@EXAMPLE.COM.';$normalized['mail_from_local_part']='Notify';$cases['real_sender_normalization']=$normalized;
    $boolean=$base;$boolean['announcement_email']['enabled']=true;$boolean['announcement_email']['recipients'][0]['enabled']=true;$cases['boolean_flags']=$boolean;
    foreach($cases as $name=>$raw){
        $write($raw);$fixture=new \FreePBX\modules\DeepEmailSnapshotFixture();$target=$fixture->target($id);$fingerprint=$fixture->fingerprint($target);
        $hashes=$fixture->capture($id,$fingerprint);$context=['recipient_id'=>$id,'target_hashes'=>$hashes,'expires_at'=>time()+300,'schedule_deadline'=>null];
        $check(count($hashes)>=1&&count($hashes)<=3&&in_array(Policy::emailTargetHash($raw,$id),$hashes,true), $name.': normalized getter was not bound to raw projection');
        $check(Policy::permitsEmail($raw,$context),$name.': unchanged effective sender was suppressed');
        $changed=$raw;$changed['operator_auth']=['totp_counter'=>42];$write($changed);
        $check(Policy::permitsEmail($changed,$context),$name.': unrelated MFA update suppressed email');
        $defaulted=$fixture->defaulted();$defaulted['operator_auth']=['totp_counter'=>43];$write($defaulted);
        $check(Policy::permitsEmail($defaulted,$context),$name.': real loader/default-merging MFA writer suppressed email');
        $normalized=$fixture->settings();$normalized['operator_auth']=['totp_counter'=>44];$write($normalized);
        $check(Policy::permitsEmail($normalized,$context),$name.': normalized operator settings save suppressed unchanged email');
        $changed['announcement_email']['recipients'][0]['address']='changed@example.com';$write($changed);
        $check(!Policy::permitsEmail($changed,$context),$name.': changed raw route kept authority');
        $check($fixture->capture($id,$fingerprint)===[],$name.': stale frozen target blessed a new projection');
    }
    $write($base);$fixture=new \FreePBX\modules\DeepEmailSnapshotFixture();$fingerprint=$fixture->fingerprint($fixture->target($id));
    $GLOBALS['sls_email_snapshot_race']=static function()use($base,$write){$changed=$base;$changed['mail_from_domain']='changed.example.com';$write($changed);};
    $blocked=false;try{$blocked=$fixture->capture($id,$fingerprint)===[];}catch(RuntimeException $error){$blocked=true;}
    $check($blocked,'Replacement during actual protected read blessed a mismatched normalized/raw snapshot');
    $check($fixture->capture($id,$fingerprint)===[],'A changed source was accepted after reversible snapshot race');
    $check(!Policy::permits($base,['recipient_id'=>$id,'target_hashes'=>[Policy::emailTargetHash($base,$id)],'expires_at'=>time()+300,'schedule_deadline'=>null]),'Email input silently broadened old webhook permits contract');
    echo "Actual getter/loader/sender block and raw policy capture: $checks checks passed; no PBX/provider effects.\n";
} finally {
    $GLOBALS['sls_email_snapshot_race']=null;
    foreach(glob($root.'/*')?:[]as $path)unlink($path);rmdir($root);
}
}
