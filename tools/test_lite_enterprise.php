<?php
declare(strict_types=1);
require_once __DIR__.'/../slsmassnotifyserver/EnterpriseAdministration.php';
require_once __DIR__.'/../slsmassnotifyserver/EnterpriseIdentityConfig.php';
require_once __DIR__.'/../slsmassnotifyserver/EnterpriseIdentityManagement.php';
require_once __DIR__.'/../slsmassnotifyserver/api/sls-mass-notify/contract.php';
use SLS\MassNotify\{EnterpriseLabsConfig as Labs,RuntimeState,EnterpriseIdentityConfig};
function liteCheck(bool $value,string $message):void { if(!$value){throw new RuntimeException($message);} }
function liteReject(callable $work):void {
    try {$work();} catch(DomainException $error) {
        liteCheck(str_contains($error->getMessage(),'Lite'),'The operation failed for an unrelated reason.');return;
    }
    throw new RuntimeException('Lite admitted an Enterprise operation.');
}
function load_view($path,$variables=[]):string {extract($variables);ob_start();include $path;return ob_get_clean();}
$settings=['deployment_profile'=>'lite','enterprise_labs'=>['enabled'=>true],
    'enterprise_identity'=>['enabled'=>true,'providers'=>[],'grants'=>[]],
    'enterprise_integrations'=>['enabled'=>'1','meetings'=>['enabled'=>'1','zoom_access_token'=>'retained-fixture-secret']],
    'enterprise_operations'=>['enabled'=>true],'enterprise_cluster'=>['enabled'=>true]];
liteCheck(!Labs::enabled($settings),'Lite accepted a stored Enterprise master flag.');
liteCheck(!RuntimeState::labsEnabled($settings),'Raw PHP runtime admitted Enterprise in Lite.');
liteCheck(!\SLS\MassNotify\EnterpriseClusterConfig::enabled($settings),'Raw PHP configuration enabled clustering in Lite.');
liteCheck(!\SLS\MassNotify\ControlContract::labsEnabled($settings),'The Control API admitted stored Enterprise flags in Lite.');
liteCheck(\SLS\MassNotify\ControlContract::effectiveLabs($settings)['enterprise_identity']['enabled']===false,
    'The Control API exposed enterprise SSO as enabled in Lite.');
liteCheck(RuntimeState::running($settings),'Lite stopped ordinary notification admission.');
liteReject(fn()=>Labs::requireEnabled($settings));
liteReject(fn()=>Labs::assertActivation($settings));
liteReject(fn()=>Labs::changes($settings,true,array_fill_keys(array_column(Labs::catalog(),'id'),false)));
liteReject(fn()=>EnterpriseIdentityConfig::provider($settings,'idp_fixture'));
$masked=Labs::disableWhenOff($settings);
liteCheck($masked['enterprise_labs']['enabled']===false&&$masked['enterprise_identity']['enabled']===false,
    'Lite did not mask stored activation flags.');
liteCheck($masked['enterprise_integrations']['enabled']==='0'&&$masked['enterprise_operations']['enabled']===false,
    'Lite retained an active Enterprise section.');
liteCheck($masked['enterprise_integrations']['meetings']['zoom_access_token']==='retained-fixture-secret',
    'Lite discarded saved Enterprise credentials.');
$standard=$settings;$standard['deployment_profile']='standard';
liteCheck(Labs::enabled($standard)&&RuntimeState::labsEnabled($standard),'Standard Enterprise behavior changed.');
class LiteEnterpriseFixture {
    use \FreePBX\modules\SlsEnterpriseAdministration;
    use \FreePBX\modules\SlsEnterpriseLabs;
    const SETTINGS_JSON='/unused-lite-profile-fixture/active.config';
    const PENDING_SETTINGS_JSON='/unused-lite-profile-fixture/pending.config';
    public function currentOperator():array{return ['id'=>'recovery_admin','operator_role'=>'administrator','username'=>'fixture'];}
    public function getActiveSettings():array{return $GLOBALS['settings'];}
    public function saveLabs():void{$this->saveEnterpriseNamespaces(['enterprise_integrations'=>['enabled'=>'1']]);}
}
$module=new LiteEnterpriseFixture;
liteReject(fn()=>$module->saveLabs());
$rejectedIdentity=$module->enterpriseLabsAction('identity_save',[]);
liteCheck(($rejectedIdentity['success']??true)===false&&str_contains($rejectedIdentity['message']??'','Lite'),
    'The separate SSO controller accepted a Lite action or hid its profile restriction.');
liteCheck(str_contains($module->renderOperatorIdentitySettings('/fixture','fixture'),'unavailable in Lite'),
    'Operator Access did not explain the enterprise SSO restriction.');
liteReject(fn()=>$module->enterpriseAdministratorAction('danger_begin',['feature'=>'enterprise_labs']));
$html=$module->renderEnterpriseLabsDashboard();
liteCheck(str_contains($html,'Lite')&&str_contains($html,'Enterprise Labs')&&str_contains($html,'--standard'),
    'The Enterprise page did not explain the Lite restriction.');
liteCheck(!str_contains($html,'sls-labs-master')&&!str_contains($html,'enterprise.js'),
    'Lite rendered an Enterprise activation control.');
class LiteEnterpriseLockedFixture extends LiteEnterpriseFixture {
    public array $active=['deployment_profile'=>'standard'];
    public int $writes=0;
    public function getActiveSettings():array{return $this->active;}
    public function acquireAnnouncementActivityLock(...$unused){return fopen('php://temp','w+b');}
    public function acquireSettingsLock(...$unused){$this->active['deployment_profile']='lite';return fopen('php://temp','w+b');}
    public function releaseSettingsLock($lock):void{fclose($lock);}
    public function releaseNativeBackupFileLock($lock):void{fclose($lock);}
    public function loadSettingsFile($path):array{return $this->active;}
    public function normalizeSettings(array $value):array{return $value;}
    public function configurationPathMetadata($path){return null;}
    public function writeSettingsFileUnlocked(...$unused):void{$this->writes++;}
}
$concurrent=new LiteEnterpriseLockedFixture;
$rejectedConcurrentIdentity=$concurrent->enterpriseLabsAction('identity_save',[]);
liteCheck(($rejectedConcurrentIdentity['success']??true)===false
    &&str_contains($rejectedConcurrentIdentity['message']??'','Lite')&&$concurrent->writes===0,
    'The separate SSO controller did not recheck the locked deployment profile.');
$helper=realpath(__DIR__.'/../slsmassnotifyserver/bin/sls_mass_notify');
$python= <<<'PY'
import json,sys
sys.path.insert(0,sys.argv[1])
import sls_cluster_guard as guard
import sls_notify as notify
s={'deployment_profile':'lite','enterprise_labs':{'enabled':True},'enterprise_cluster':{'enabled':True},
   'enterprise_integrations':{'enabled':'1','radios':{'enabled':'1','devices':[{'extension':'1000','enabled':'1'}]}}}
assert guard.labs_enabled(s) is False
assert guard.enabled(s) is False
assert notify.radio_gateway_extensions(s)==[]
s['deployment_profile']='standard'
assert guard.labs_enabled(s) is True
assert notify.radio_gateway_extensions(s)==['1000']
print('Lite Python runtime gates passed.')
PY;
$pipes=[];$process=proc_open(['/usr/bin/python3','-I','-c',$python,$helper],
    [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
$stdout=stream_get_contents($pipes[1]);$stderr=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
liteCheck(proc_close($process)===0,'Python Lite gate failed: '.$stdout.$stderr);
echo "Lite Enterprise: stored flags, provider/administrator boundaries, retained credentials, normal notifications and real PHP/Python runtime gates passed.\n";
