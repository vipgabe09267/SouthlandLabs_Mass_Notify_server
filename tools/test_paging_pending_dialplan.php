<?php
declare(strict_types=1);
require dirname(__DIR__).'/slsmassnotifyserver/Paging.php';
class extension { public $arguments; public function __construct(...$arguments){$this->arguments=$arguments;} }
class ext_setvar extends extension {} class ext_hangup extends extension {} class ext_gosub extends extension {} class ext_return extends extension {}
class PagingGeneration {
    use \FreePBX\modules\SlsLivePaging;
    const RUNTIME_DIR='/fixture/runtime';
    public $active,$pending,$prepared;
    private function applyPendingSettingsTransaction($pbxReload=false,$dialplanHook=false){$this->active=$this->pending;$this->pending=null;}
    private function getActiveSettings(){return $this->active;}
    private function getPendingSettings(){return $this->pending;}
    private function rawSettingsForPbxReload($settings,$pending){return $settings;}
    private function validateLivePagingSelection($paging,$settings){}
    private function assertLivePagingExtensionAvailable($extension){}
    private function ensureLivePagingPrompts($settings){$this->prepared=$settings;}
}
class DialplanGeneration {
    public $entries=[],$includes=[];
    public function add($context,$extension,$label,$application){$this->entries[] = [$context,$extension,$application];}
    public function addInclude($context,$include){$this->includes[]=[$context,$include];}
}
$module=new PagingGeneration();
$module->active=['live_paging'=>array_replace(\SLS\MassNotify\LivePagingConfig::defaults(),['enabled'=>'0','extension'=>'799'])];
$module->pending=['live_paging'=>array_replace(\SLS\MassNotify\LivePagingConfig::defaults(),['enabled'=>'1','extension'=>'799','external_access'=>'1','external_ivr_ids'=>['2'], 'allowed_callers'=>['1000'], 'groups'=>[['group_id'=>'fixture_group','menu_number'=>1,'require_pin'=>'1','pin_length'=>4,'pin_hash'=>password_hash('1234',PASSWORD_DEFAULT)]]])];
$expectedPaging=$module->pending;
$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
$pairs=array_map(static fn($row)=>array_slice($row,0,2),$dialplan->entries);
if (!in_array(['sls-live-paging','799'],$pairs,true) || !in_array(['ivr-2','799'],$pairs,true) || in_array(['ivr-1','799'],$pairs,true)
    || !in_array(['from-internal-additional','sls-live-paging'],$dialplan->includes,true) || $module->prepared!==$expectedPaging) { throw new RuntimeException('Pending paging settings did not generate the selected internal/IVR routes.'); }
$ready=array_values(array_filter($dialplan->entries,static fn($row)=>$row[0]==='sls-live-paging-ready'));
if(count($ready)!==2 || $ready[0][1]!=='s' || $ready[1][1]!=='s'
    || get_class($ready[0][2])!==extension::class || get_class($ready[1][2])!==extension::class
    || $ready[0][2]->arguments!==['AGI(/fixture/runtime/sls_mass_notify_live_paging.php,--ready)']
    || $ready[1][2]->arguments!==['StopPlayTones()']) {
    throw new RuntimeException('Caller-ready menu context must invoke the fixed AGI, stop its tone last, and fall through without consuming the IVR/Gosub stack.');
}
foreach($dialplan->includes as $include){if($include[1]==='sls-live-paging-ready'){throw new RuntimeException('Caller-ready callback was exposed through a general dialplan include.');}}
$module->active=$expectedPaging;$module->pending=['live_paging'=>array_replace(\SLS\MassNotify\LivePagingConfig::defaults(),['enabled'=>'0'])];
$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
if ($dialplan->entries) { throw new RuntimeException('Pending disable kept the old active paging route.'); }
echo "Paging Apply Config: pending enable/disable, prompt revision and exact selected-IVR routing passed.\n";


// Exercise actual hooks, transaction and audience normalization. Only protected
// read/write storage, native DB/conflict lookup and voice generation are inert
// boundaries; a removed reference must never grant broader phone permission.
require_once dirname(__DIR__).'/slsmassnotifyserver/Automations.php';
if(!interface_exists('BMO')){interface BMO {}}
require_once dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
class ReloadAudienceSource extends \FreePBX\modules\Slsmassnotifyserver {public array $fixtureConfigured=[];public function getConfiguredPjsipExtensionNumbers(){return $this->fixtureConfigured;}}
$reloadReflection=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
$reloadSource=file($reloadReflection->getFileName());$reloadMethods='';
foreach(['genConfig','applySettings','applyPendingSettingsTransaction','unchangedLegacyPagingAudienceIds'] as $methodName){
    $method=$reloadReflection->getMethod($methodName);
    $reloadMethods.=implode('',array_slice($reloadSource,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));
}
$reloadFixture=<<<'PHP'
class DeletedExtensionReload {
    use \FreePBX\modules\SlsLivePaging;
    use \FreePBX\modules\SlsAutomations;
    const RUNTIME_DIR='/fixture/runtime';
    const SETTINGS_JSON='/fixture/active';
    const PENDING_SETTINGS_JSON='/fixture/pending';
    const LEGACY_SETTINGS_JSON='/fixture/legacy-active';
    const LEGACY_OLD_SETTINGS_JSON='/fixture/old-active';
    const LEGACY_PENDING_SETTINGS_JSON='/fixture/legacy-pending';
    const LEGACY_OLD_PENDING_SETTINGS_JSON='/fixture/old-pending';
    public array $settings;
    public ?array $pending=null;
    public string $pendingLocation=self::PENDING_SETTINGS_JSON;
    public array $configured=['1000','1001'];
    public array $ivrs=[['id'=>'1','name'=>'Fixture IVR','entries'=>[]]];
    public bool $databaseFailure=false;
    public bool $conflict=false;
    public bool $mutateDuringRawRead=false;
    public bool $rawTargetRace=false;
    public bool $stableMetadata=false;
    public int $writes=0;
    public array $prepared=[];
    public array $unavailablePrompts=[];
    public bool $unsafePrompt=false;
    public ?string $capacityReport=null;
    public bool $transientBatchRefusal=false;
    public bool $approvedRuntime=true;
    public bool $removePendingUponLock=false;
    public array $cacheChecks=[];
    private function requireRuntimeAccount(){if(!$this->approvedRuntime){throw new RuntimeException('wrong-runtime-account');}}
    private array $normalizedSettingsCache=[];
    public $FreePBX;
    public function __construct(array $settings) {
        $this->settings=$settings;
        $this->FreePBX=(object)['Extensions'=>new class {
            public function checkUsage($extensions,$report) { return []; }
        }];
    }
    private function validateAnnouncementGroupFields(array $groups){$r=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);return $r->getMethod('validateAnnouncementGroupFields')->invoke($r->newInstanceWithoutConstructor(),$groups);}
    private function normalizeSettings(array $settings,?array $protectedSource=null){
        $reflection=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
        $native=(new ReflectionClass(ReloadAudienceSource::class))->newInstanceWithoutConstructor();$native->fixtureConfigured=$this->configured;
        $retained=$this->unchangedLegacyPagingAudienceIds($settings,$protectedSource);
        $settings['announcement_groups']=$reflection->getMethod('normalizeAnnouncementGroupsForExtensions')->invoke(
            $native,$settings['announcement_groups']??[],$this->configured,null,$retained);
        $settings['live_paging']=\SLS\MassNotify\LivePagingConfig::normalize($settings['live_paging']??[]);
        $settings['automations']=\SLS\MassNotify\AutomationConfig::normalize($settings['automations']??[]);
        return $settings;
    }
    private function migrateConfigCompatibility($settings){return $settings;}
    private function normalizeAnnouncementGroupsForExtensions($groups,$allowed,$desktops=null,$retained=[]){$r=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);return $r->getMethod('normalizeAnnouncementGroupsForExtensions')->invoke($r->newInstanceWithoutConstructor(),$groups,$allowed,$desktops,$retained);}
    public function normalizeProposal($settings){return $this->normalizeSettings($settings);}
    private function getActiveSettings(){return $this->normalizeSettings($this->settings,$this->settings);}
    private function getPendingSettings(){return $this->pending===null?null:\SLS\MassNotify\ImmediateSettings::reconcile($this->getActiveSettings(),$this->normalizeSettings($this->pending,$this->pending));}
    private function loadSettingsFile($path){
        $raw=$path===self::SETTINGS_JSON?$this->settings:$this->pending;
        if($this->rawTargetRace){$this->settings['announcement_groups'][0]['extensions']=$this->settings['announcement_groups'][0]['extensions']===['1002']?['1003']:['1002'];}
        if($this->mutateDuringRawRead){$this->settings['runtime_enabled']=!($this->settings['runtime_enabled']??true);}
        if(!is_array($raw)){throw new RuntimeException('Fixture path is absent.');}
        return $raw;
    }
    private function settingsCacheFingerprint($path){return $this->stableMetadata?'same-metadata':hash('sha256',serialize($path===self::SETTINGS_JSON?$this->settings:$this->pending));}
    private function settingsFileFingerprint($path){return hash('sha256',serialize($path===self::SETTINGS_JSON?$this->settings:$this->pending));}
    private function configurationPathMetadata($path){return ($path===self::SETTINGS_JSON||($path===$this->pendingLocation&&$this->pending!==null))?['mode'=>0100600]:null;}
    private function ensurePluginDataDir(){}
    private function acquireSettingsLock($exclusive){if($this->removePendingUponLock){$this->pending=null;}return null;}
    private function releaseSettingsLock($lock){}
    private function isSetupComplete($settings){return false;}
    private function writeSettingsFileUnlocked($path,$settings,$backup){$this->writes++;$this->settings=$settings;}
    private function removePendingSettingsFileUnlocked($message){$this->pending=null;}
    public function getConfiguredPjsipExtensionNumbers(){if($this->databaseFailure){throw new RuntimeException('native-database-unavailable');}return $this->configured;}
    public function getAllPjsipExtensions(){return array_map(static fn($id)=>['extension'=>$id,'registered'=>false],$this->getConfiguredPjsipExtensionNumbers());}
    public function getRegisteredPjsipExtensions(){throw new LogicException('Registration loss is not extension deletion.');}
    public function getLivePagingIvrs(): array {return $this->ivrs;}
    protected function queryLivePagingIvr(string $id): ?array {
        if($this->databaseFailure){throw new RuntimeException('native-database-unavailable');}
        foreach($this->ivrs as $ivr){if($ivr['id']===$id){return $ivr;}}return null;
    }
    protected function queryLivePagingDialplan($extension){return $this->conflict?"[ Context 'other' created by 'pbx_config' ]\n '799' => 1. Hangup() [fixture]":"There is no existence of '".$extension."' in context 'from-internal'";}
    private function ensureLivePagingPrompts($settings,bool $cachedOnly=false){
        $this->prepared[]=$settings;$this->cacheChecks[]=$cachedOnly;
        if($this->unsafePrompt){throw new RuntimeException('unsafe-prompt-path');}
        if($this->transientBatchRefusal&&!$cachedOnly&&count($settings['automations']['rules']??[])>1){throw new \FreePBX\modules\SlsPagingPromptUnavailableException('fixture-batch-busy');}
        $texts=\SLS\MassNotify\LivePagingConfig::promptTexts(\SLS\MassNotify\LivePagingConfig::normalize($settings['live_paging']??[]),$settings['announcement_groups']??[],$settings['automations']??[]);
        if(array_intersect($this->unavailablePrompts,$texts)){
            if($this->capacityReport!==null){throw \FreePBX\modules\SlsPagingPromptUnavailableException::fromCapacityReport($this->capacityReport);}
            throw new \FreePBX\modules\SlsPagingPromptUnavailableException('fixture-prompt-unavailable');
        }
    }
    public function strictPagingValidation(){return $this->validateLivePagingSelection($this->settings['live_paging'],$this->getActiveSettings());}
}
PHP;
$reloadFixture=substr($reloadFixture,0,-1).$reloadMethods.'}';eval($reloadFixture);
function deletedReloadCheck(bool $value,string $message): void {if(!$value){throw new RuntimeException($message);}}
function reloadHasContext($dialplan,string $context): bool {return (bool)array_filter($dialplan->entries,static fn($row)=>$row[0]===$context);}
$reloadFailures=[];
function reloadCase(string $name,callable $case): void {global $reloadFailures;try{$case();echo 'PASS '.$name."\n";}catch(Throwable $error){$reloadFailures[]=$name.': '.$error->getMessage();echo 'FAIL '.$name.': '.$error->getMessage()."\n";}}
$reloadWarnings=tempnam(sys_get_temp_dir(),'sls-reload-warnings-');$previousErrorLog=ini_get('error_log');ini_set('error_log',$reloadWarnings);
register_shutdown_function(static function()use($reloadWarnings,$previousErrorLog):void{ini_set('error_log',$previousErrorLog);if(is_file($reloadWarnings)){unlink($reloadWarnings);}});
$validSettings=['announcement_groups'=>[], 'live_paging'=>array_replace(\SLS\MassNotify\LivePagingConfig::defaults(),[
    'enabled'=>'1','extension'=>'799','groups'=>[['group_id'=>'independent_office','menu_number'=>1,
        'require_pin'=>'0','pin_length'=>4,'pin_hash'=>'','name'=>'Office','extensions'=>['1001'],
        'notify_extensions'=>['1001'],'allowed_callers'=>['1000'],'text_message'=>'private-fixture-marker']]])];
foreach(['audio'=>'extensions','text'=>'notify_extensions','caller'=>'allowed_callers'] as $label=>$field){
    reloadCase('deleted '.$label.' omits affected menu',static function()use($validSettings,$field){
        $settings=$validSettings;$settings['live_paging']['groups'][0][$field][]='1002';
        $module=new DeletedExtensionReload($settings);$before=serialize([$module->settings,$module->pending]);$dialplan=new DialplanGeneration();
        $module->doDialplanHook($dialplan,'asterisk',500);
        deletedReloadCheck(!reloadHasContext($dialplan,'sls-live-paging')&&$module->prepared===[],'Affected menu was published or generated voices.');
        deletedReloadCheck(serialize([$module->settings,$module->pending])===$before&&$module->writes===0,'Global reload rewrote stored settings.');
        try{$module->strictPagingValidation();throw new LogicException('Direct validation accepted removed object.');}catch(InvalidArgumentException $expected){}
    });
}
foreach(['extensions','allowed_callers'] as $field){
    reloadCase('last '.$field.' never defaults to everyone',static function()use($validSettings,$field){
        $settings=$validSettings;$settings['live_paging']['groups'][0][$field]=['1002'];
        $module=new DeletedExtensionReload($settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
        deletedReloadCheck($dialplan->entries===[],'An empty effective authorization/target list published a route.');
    });
}
reloadCase('unused legacy caller cannot block independent menu',static function()use($validSettings){
    $settings=$validSettings;$settings['live_paging']['allowed_callers']=['1002'];$module=new DeletedExtensionReload($settings);$before=serialize($module->settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(reloadHasContext($dialplan,'sls-live-paging')&&serialize($module->settings)===$before,'Unused legacy caller blocked or rewrote independent menu.');
});
reloadCase('configured offline phones retain route and warning clears',static function()use($validSettings,$reloadWarnings){
    $before=file_get_contents($reloadWarnings);$module=new DeletedExtensionReload($validSettings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(reloadHasContext($dialplan,'sls-live-paging'),'Offline but configured phones lost routing.');
    deletedReloadCheck(file_get_contents($reloadWarnings)===$before,'Fixed configuration kept warning.');
});
reloadCase('stale pending defers before writes and uses active routes',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->pending['live_paging']['extension']='798';$module->pending['live_paging']['groups'][0]['allowed_callers']=['1002'];
    $before=serialize([$module->settings,$module->pending]);
    foreach(['hook-first','config-first'] as $order){
        $dialplan=new DialplanGeneration();if($order==='hook-first'){$module->doDialplanHook($dialplan,'asterisk',500);$module->genConfig();}else{$module->genConfig();$module->doDialplanHook($dialplan,'asterisk',500);}
        $pairs=array_map(static fn($row)=>array_slice($row,0,2),$dialplan->entries);
        deletedReloadCheck(in_array(['sls-live-paging','799'],$pairs,true)&&!in_array(['sls-live-paging','798'],$pairs,true),'Deferred pending route disagrees with active config.');
        deletedReloadCheck($module->writes===0&&serialize([$module->settings,$module->pending])===$before,'Deferred pending changed bytes or removed staged settings.');
    }
    deletedReloadCheck($module->applySettings()['success']===false&&$module->writes===0,'Direct SLL apply accepted stale pending.');
});
$legacySettings=$validSettings;$legacySettings['announcement_groups']=[['id'=>'grp_aaaaaaaaaaaa','name'=>'Old audience','extensions'=>['1002'],'desktop_clients'=>[]]];
$legacySettings['live_paging']['allowed_callers']=['1000'];$legacySettings['live_paging']['groups']=[['group_id'=>'grp_aaaaaaaaaaaa','menu_number'=>1,'require_pin'=>'0','pin_length'=>4,'pin_hash'=>'']];
reloadCase('raw legacy witness identifies last deleted native phone',static function()use($legacySettings,$validSettings){
    $module=new DeletedExtensionReload($legacySettings);$before=serialize($module->settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck($dialplan->entries===[]&&serialize($module->settings)===$before,'Deleted last legacy phone created/rewrote a group.');
    $module=new DeletedExtensionReload($validSettings);$module->pending=$legacySettings;$before=serialize([$module->settings,$module->pending]);$module->genConfig();
    deletedReloadCheck($module->writes===0&&serialize([$module->settings,$module->pending])===$before,'Legacy pending deferral lost its original snapshot.');
});
foreach(['missing group','malformed raw selectors','duplicate raw selectors','changed raw snapshot','native DB failure','dialplan conflict'] as $fault){
    reloadCase('strict '.$fault,static function()use($fault,$legacySettings,$validSettings){
        $module=new DeletedExtensionReload(str_contains($fault,'raw')||$fault==='missing group'?$legacySettings:$validSettings);
        if($fault==='missing group'){$module->settings['announcement_groups']=[];}
        if($fault==='malformed raw selectors'){$module->settings['announcement_groups'][0]['extensions']=['1002,Hangup()'];}
        if($fault==='duplicate raw selectors'){$module->settings['announcement_groups'][0]['extensions']=['1002','1002'];}
        if($fault==='changed raw snapshot'){$module->mutateDuringRawRead=true;}
        if($fault==='native DB failure'){$module->databaseFailure=true;}
        if($fault==='dialplan conflict'){$module->conflict=true;}
        $dialplan=new DialplanGeneration();try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Strict failure was silently treated as a deleted PBX object.');}
        catch(InvalidArgumentException|RuntimeException $expected){}
        deletedReloadCheck($module->writes===0,'Strict failure wrote config.');
    });
}
reloadCase('deleted IVR omitted only after successful query',static function()use($validSettings){
    $settings=$validSettings;$settings['live_paging']['external_access']='1';$settings['live_paging']['external_ivr_ids']=['2'];
    $module=new DeletedExtensionReload($settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck($dialplan->entries===[],'Missing selected IVR exposed a paging route.');
    $module=new DeletedExtensionReload($settings);$module->databaseFailure=true;
    try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('IVR DB failure became deletion.');}
    catch(RuntimeException $expected){deletedReloadCheck($expected->getMessage()==='native-database-unavailable','Wrong strict DB error.');}
});
$panicAction=\SLS\MassNotify\AutomationConfig::action(['id'=>'act_'.str_repeat('d',24),'name'=>'Fixture device','kind'=>'brightsign_udp','enabled'=>true,'host'=>'192.168.1.20','port'=>5000,'message'=>'fixture']);
$panicRule=\SLS\MassNotify\AutomationConfig::rule(['id'=>'trg_'.str_repeat('a',24),'name'=>'Native panic','kind'=>'panic','enabled'=>true,
    'secret'=>str_repeat('b',64),'location_id'=>'loc_'.str_repeat('c',24),'dial_extension'=>'8998','callers'=>['1002'],'action_ids'=>['act_'.str_repeat('d',24)]]);
function routePairs($dialplan): array {return array_map(static fn($r)=>array_slice($r,0,2),$dialplan->entries);}
foreach(['hook-first','genConfig-first'] as $order){
    foreach(['ready','unavailable'] as $availability){
        reloadCase("$order with $availability staged prompt",static function()use($validSettings,$panicRule,$panicAction,$order,$availability){
            $staged=$validSettings;$staged['live_paging']['extension']='798';$staged['live_paging']['menu_prompt']='Staged private menu.';
            $panic=$panicRule;$panic['callers']=['1000'];$staged['automations']=['schema'=>1,'rules'=>[$panic],'actions'=>[$panicAction]];
            $module=new DeletedExtensionReload($validSettings);$module->pending=$staged;
            if($availability==='unavailable'){$module->unavailablePrompts=['Staged private menu.'];}
            $before=serialize([$module->settings,$module->pending]);$dialplan=new DialplanGeneration();
            if($order==='genConfig-first'){$module->genConfig();}
            $module->doDialplanHook($dialplan,'asterisk',500);
            // A different FreePBX caller can invoke genConfig later, after a
            // previously saturated renderer recovers. It must agree with the
            // routes that the dialplan hook already published on this reload.
            $later=new DeletedExtensionReload($module->settings);$later->pending=$module->pending;
            if($order==='hook-first'){$later->genConfig();}
            $pairs=routePairs($dialplan);
            if($availability==='ready'){
                deletedReloadCheck($module->writes===1&&$later->pending===null&&$later->settings['live_paging']['extension']==='798','Valid staged routing was not activated before publication.');
                deletedReloadCheck(in_array(['sls-live-paging','798'],$pairs,true)&&in_array(['sls-trigger-panic','8998'],$pairs,true)&&!in_array(['sls-live-paging','799'],$pairs,true),'Healthy revision did not generate exactly its chosen routes.');
            }else{
                deletedReloadCheck($module->writes+$later->writes===0&&serialize([$later->settings,$later->pending])===$before,'Unavailable staged audio changed a protected revision.');
                deletedReloadCheck(in_array(['sls-live-paging','799'],$pairs,true)&&!in_array(['sls-live-paging','798'],$pairs,true)&&!in_array(['sls-trigger-panic','8998'],$pairs,true),'Unavailable staged media suppressed the last good menu or leaked a new route.');
                deletedReloadCheck(end($module->cacheChecks)===true,'Deferred staged audio started another speech job to reconstruct the active menu.');
                $result=$module->applySettings();
                deletedReloadCheck($result['success']===false&&$result['errors']===['fixture-prompt-unavailable'],'Direct SLL apply lost the explicit media failure.');
            }
        });
    }
}
reloadCase('unavailable active panic keeps playable panic and paging routes',static function()use($validSettings,$panicRule,$panicAction){
    $one=$panicRule;$one['callers']=['1000'];$one['confirmation_prompt']='First private prompt.';
    $two=$one;$two['id']='trg_'.str_repeat('e',24);$two['dial_extension']='8999';$two['confirmation_prompt']='Second private prompt.';
    $settings=$validSettings;$settings['automations']=['schema'=>1,'rules'=>[$one,$two],'actions'=>[$panicAction]];
    $module=new DeletedExtensionReload($settings);$module->unavailablePrompts=[$one['confirmation_prompt']];$dialplan=new DialplanGeneration();
    $module->doDialplanHook($dialplan,'asterisk',500);$pairs=routePairs($dialplan);
    deletedReloadCheck(!in_array(['sls-trigger-panic','8998'],$pairs,true)&&in_array(['sls-trigger-panic','8999'],$pairs,true)&&in_array(['sls-live-paging','799'],$pairs,true),'An unavailable active prompt changed another playable route.');
    deletedReloadCheck($module->cacheChecks===[false,true,true,false],'Failed active panic batch tried to render every shortcut again.');
    deletedReloadCheck($module->writes===0&&$module->settings===$settings,'Active prompt failure edited saved authorization.');
});
reloadCase('a recovered active batch reports only actual omissions',static function()use($validSettings,$panicRule,$panicAction,$reloadWarnings){
    $active=$validSettings;$active['live_paging']=\SLS\MassNotify\LivePagingConfig::defaults();
    $one=$panicRule;$one['callers']=['1000'];$two=$one;$two['id']='trg_'.str_repeat('e',24);$two['dial_extension']='8999';
    $active['automations']=['schema'=>1,'rules'=>[$one,$two],'actions'=>[$panicAction]];
    $module=new DeletedExtensionReload($active);$module->transientBatchRefusal=true;$dialplan=new DialplanGeneration();
    $before=file_get_contents($reloadWarnings);$module->doDialplanHook($dialplan,'asterisk',500);$after=file_get_contents($reloadWarnings);
    deletedReloadCheck(in_array(['sls-trigger-panic','8999'],routePairs($dialplan),true)&&in_array(['sls-trigger-panic','8998'],routePairs($dialplan),true),'Playable shortcuts disappeared after a transient refusal.');
    deletedReloadCheck($before===$after,'Reload warned of an omitted route after verifying every active route playable.');
});
reloadCase('ordinary reload and direct apply retain only measured capacity fields',static function()use($validSettings,$reloadWarnings){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->pending['live_paging']['menu_prompt']='Private staged paging.';
    $module->unavailablePrompts=[$module->pending['live_paging']['menu_prompt']];
    $module->capacityReport='role=data available_bytes=4194304 required_bytes=357011456 private-fixture-marker role=private-host malformed=7';
    $before=file_get_contents($reloadWarnings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    $notice=substr(file_get_contents($reloadWarnings),strlen($before));$apply=$module->applySettings();
    deletedReloadCheck($apply['success']===false&&$module->writes===0&&count($apply['errors'])===1,'Explicit SLL apply lost its capacity failure.');
    foreach([$notice,$apply['errors'][0]] as $detail){
        deletedReloadCheck(str_contains($detail,'role=data available_bytes=4194304 required_bytes=357011456')&&!str_contains($detail,'private-host')&&!str_contains($detail,'private-fixture-marker')&&!str_contains($detail,'malformed'),'Capacity report leaked private worker output or lost a measured field.');
    }
});
reloadCase('first panic shortcut with unavailable audio preserves the staged revision',static function()use($validSettings,$panicRule,$panicAction){
    $active=$validSettings;$active['live_paging']=\SLS\MassNotify\LivePagingConfig::defaults();
    $pending=$active;$rule=$panicRule;$rule['callers']=['1000'];$rule['confirmation_prompt']='Deferred panic confirmation.';
    $pending['automations']=['schema'=>1,'rules'=>[$rule],'actions'=>[$panicAction]];
    $module=new DeletedExtensionReload($active);$module->pending=$pending;$module->unavailablePrompts=[$rule['confirmation_prompt']];
    $dialplan=new DialplanGeneration();$dialplan->add('from-internal','1000','',new ext_hangup());
    $module->genConfig();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(routePairs($dialplan)===[['from-internal','1000']]&&$dialplan->includes===[],'A new, unplayable panic shortcut interfered with an unrelated Core route.');
    deletedReloadCheck($module->settings===$active&&$module->pending===$pending&&$module->writes===0,'Failed first panic prompt changed the protected revisions.');
});
reloadCase('active paging failure keeps a playable panic shortcut',static function()use($validSettings,$panicRule,$panicAction){
    $active=$validSettings;$rule=$panicRule;$rule['callers']=['1000'];
    $active['automations']=['schema'=>1,'rules'=>[$rule],'actions'=>[$panicAction]];
    $active['live_paging']['menu_prompt']='Unavailable active menu.';
    $module=new DeletedExtensionReload($active);$module->unavailablePrompts=[$active['live_paging']['menu_prompt']];
    $dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(in_array(['sls-trigger-panic','8998'],routePairs($dialplan),true)&&!reloadHasContext($dialplan,'sls-live-paging'),'Unplayable active paging suppressed a valid panic shortcut.');
});
reloadCase('pending consumed while waiting for lock cannot write active twice',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->removePendingUponLock=true;
    $dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck($module->writes===0&&$module->pending===null&&in_array(['sls-live-paging','799'],routePairs($dialplan),true),'A native caller reapplied an already consumed pending revision.');
});
reloadCase('unsafe staged prompt is a strict failure before route publication',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->unsafePrompt=true;$dialplan=new DialplanGeneration();
    try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Unsafe staged prompt was downgraded to a warning.');}
    catch(RuntimeException $error){deletedReloadCheck($error->getPrevious()&&$error->getPrevious()->getMessage()==='unsafe-prompt-path','Unexpected staged trust failure.');}
    deletedReloadCheck($module->writes===0&&$module->pending===$validSettings&&$dialplan->entries===[],'Unsafe staged media produced configuration changes or routes.');
});
reloadCase('release reload uses active even when pending is playable',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->pending['live_paging']['extension']='798';
    $before=serialize([$module->settings,$module->pending]);$dialplan=new DialplanGeneration();
    $prior=getenv('SLS_MASS_NOTIFY_PRESERVE_PENDING');putenv('SLS_MASS_NOTIFY_PRESERVE_PENDING=1');
    try{
        $module->genConfig();$module->doDialplanHook($dialplan,'asterisk',500);$pairs=routePairs($dialplan);
        deletedReloadCheck($module->writes===0&&serialize([$module->settings,$module->pending])===$before&&in_array(['sls-live-paging','799'],$pairs,true)&&!in_array(['sls-live-paging','798'],$pairs,true),'Installer reload used staged routes.');
        $module->approvedRuntime=false;
        try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Untrusted caller selected preserve mode.');}
        catch(RuntimeException $e){deletedReloadCheck($e->getMessage()==='wrong-runtime-account','Wrong preservation guard error.');}
    }finally{putenv($prior===false?'SLS_MASS_NOTIFY_PRESERVE_PENDING':'SLS_MASS_NOTIFY_PRESERVE_PENDING='.$prior);}
});
reloadCase('unsafe active prompt remains a strict failure',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->unsafePrompt=true;$dialplan=new DialplanGeneration();
    try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Unsafe prompt path was suppressed.');}
    catch(RuntimeException $error){deletedReloadCheck($error->getMessage()==='unsafe-prompt-path','Unexpected strict prompt error.');}
});
reloadCase('deleted panic caller omits only that rule',static function()use($validSettings,$panicRule,$panicAction){
    $settings=$validSettings;$settings['live_paging']=\SLS\MassNotify\LivePagingConfig::defaults();$second=$panicRule;$second['id']='trg_'.str_repeat('e',24);$second['dial_extension']='8999';$second['callers']=['1000'];
    $settings['automations']=['schema'=>1,'rules'=>[$panicRule,$second],'actions'=>[$panicAction]];$module=new DeletedExtensionReload($settings);$before=serialize($settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    $pairs=array_map(static fn($row)=>array_slice($row,0,2),$dialplan->entries);
    deletedReloadCheck(!in_array(['sls-trigger-panic','8998'],$pairs,true)&&in_array(['sls-trigger-panic','8999'],$pairs,true),'Removed caller suppressed valid rule or published removed rule.');
    deletedReloadCheck(serialize($module->settings)===$before&&$module->writes===0,'Panic reload rewrote caller permissions.');
});
reloadCase('legacy pending alias is deferred without removal',static function()use($validSettings){
    $module=new DeletedExtensionReload($validSettings);$module->pendingLocation=DeletedExtensionReload::LEGACY_PENDING_SETTINGS_JSON;
    $module->pending=$validSettings;$module->pending['live_paging']['groups'][0]['allowed_callers']=['1002'];$before=serialize([$module->settings,$module->pending]);
    $module->genConfig();deletedReloadCheck($module->writes===0&&serialize([$module->settings,$module->pending])===$before,'Native reload applied active over a stale legacy pending file.');
});
reloadCase('pending panic deletion preserves both revisions',static function()use($validSettings,$panicRule,$panicAction){
    $module=new DeletedExtensionReload($validSettings);$module->pending=$validSettings;$module->pending['automations']=['schema'=>1,'rules'=>[$panicRule],'actions'=>[$panicAction]];
    $before=serialize([$module->settings,$module->pending]);$dialplan=new DialplanGeneration();$module->genConfig();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck($module->writes===0&&serialize([$module->settings,$module->pending])===$before&&reloadHasContext($dialplan,'sls-live-paging')&&!reloadHasContext($dialplan,'sls-trigger-panic'),'Stale pending panic was applied or replaced valid active routing.');
});
reloadCase('partial panic deletion never broadens caller permission',static function()use($validSettings,$panicRule,$panicAction){
    $settings=$validSettings;$settings['live_paging']=\SLS\MassNotify\LivePagingConfig::defaults();$rule=$panicRule;$rule['callers']=['1000','1002'];
    $settings['automations']=['schema'=>1,'rules'=>[$rule],'actions'=>[$panicAction]];$module=new DeletedExtensionReload($settings);$before=serialize($settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(!reloadHasContext($dialplan,'sls-trigger-panic')&&serialize($module->settings)===$before,'Partial stale panic became a different caller allowlist.');
});
class ReloadSelectedIvrQuery {
    use \FreePBX\modules\SlsLivePaging;
    public $FreePBX;
    public function read(string $id):?array{return $this->queryLivePagingIvr($id);}
}
class ReloadIvrDatabase {
    public array $queries=[];public array $ids=['1'];public array $entries=['1'];public bool $execute=true;
    public function prepare($sql){
        $database=$this;return new class($database,$sql){
            private $database,$sql;public function __construct($database,$sql){$this->database=$database;$this->sql=$sql;}
            public function execute($values){$this->database->queries[]=[$this->sql,$values];return $this->database->execute;}
            public function fetchAll($mode){return str_contains($this->sql,'SELECT id ')?$this->database->ids:$this->database->entries;}
        };
    }
}
reloadCase('dedicated native IVR query proves absence and refuses read failure',static function(){
    $database=new ReloadIvrDatabase();$module=new ReloadSelectedIvrQuery();$module->FreePBX=new class($database){private $db;public function __construct($db){$this->db=$db;}public function Database(){return $this->db;}};
    deletedReloadCheck($module->read('1')===['id'=>'1','entries'=>['1']],'Existing selected IVR did not preserve exact entries.');
    deletedReloadCheck($database->queries===[['SELECT id FROM ivr_details WHERE id = ? LIMIT 2',['1']],['SELECT selection FROM ivr_entries WHERE ivr_id = ? LIMIT 1001',['1']]],'Selected native query was not bounded and parameterized.');
    $database->ids=[];deletedReloadCheck($module->read('1')===null,'Successful empty native result was not distinguished.');
    foreach(['execute','duplicate','wrong id','oversized entries'] as $fault){
        $database->execute=$fault!=='execute';$database->ids=$fault==='duplicate'?['1','1']:($fault==='wrong id'?['2']:['1']);$database->entries=$fault==='oversized entries'?array_fill(0,1001,'1'):['1'];
        try{$module->read('1');throw new LogicException('Native IVR query accepted '.$fault);}catch(RuntimeException $expected){}
    }
});
eval('namespace FreePBX\\modules; function error_log($message){if(!empty($GLOBALS["reload_log_failure"])){throw new \\RuntimeException("fixture log handler failed");}return \\error_log($message);}');
reloadCase('warning failure cannot abort unrelated native reload',static function()use($validSettings){
    $settings=$validSettings;$settings['live_paging']['groups'][0]['extensions']=['1002'];$module=new DeletedExtensionReload($settings);$dialplan=new DialplanGeneration();$GLOBALS['reload_log_failure']=true;
    try{$module->doDialplanHook($dialplan,'asterisk',500);}finally{$GLOBALS['reload_log_failure']=false;}
    deletedReloadCheck($dialplan->entries===[]&&$module->writes===0,'Warning failure published or persisted an unsafe integration.');
});
foreach(['first group deletion','first IVR deletion','first caller deletion'] as $first){
    reloadCase('structural failure precedes '.$first,static function()use($first,$legacySettings){
        $settings=$legacySettings;
        if($first==='first group deletion'){$settings['announcement_groups'][]=['id'=>'grp_bbbbbbbbbbbb','name'=>'Malformed second','extensions'=>['1003','1003'],'desktop_clients'=>[]];$settings['live_paging']['groups'][]=['group_id'=>'grp_bbbbbbbbbbbb','menu_number'=>2,'require_pin'=>'0','pin_length'=>4,'pin_hash'=>''];}
        else{$settings['announcement_groups'][0]['extensions']=['1002','1002'];}
        if($first==='first IVR deletion'){$settings['live_paging']['external_access']='1';$settings['live_paging']['external_ivr_ids']=['2'];}
        if($first==='first caller deletion'){$settings['live_paging']['allowed_callers']=['1003'];}
        $module=new DeletedExtensionReload($settings);$dialplan=new DialplanGeneration();
        try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Early native deletion hid malformed selected legacy data.');}catch(InvalidArgumentException $expected){}
    });
}
reloadCase('raw witness binds content even when metadata and normalized projection match',static function()use($legacySettings){
    $module=new DeletedExtensionReload($legacySettings);$module->stableMetadata=true;$module->rawTargetRace=true;$dialplan=new DialplanGeneration();
    try{$module->doDialplanHook($dialplan,'asterisk',500);throw new LogicException('Changed raw evidence with the same normalized projection was accepted.');}catch(RuntimeException $expected){}
});
reloadCase('valid panic rules prepare prompts once as one batch',static function()use($validSettings,$panicRule,$panicAction){
    $settings=$validSettings;$settings['live_paging']=\SLS\MassNotify\LivePagingConfig::defaults();$first=$panicRule;$first['callers']=['1000'];$second=$first;$second['id']='trg_'.str_repeat('e',24);$second['dial_extension']='8999';
    $settings['automations']=['schema'=>1,'rules'=>[$first,$second],'actions'=>[$panicAction]];$module=new DeletedExtensionReload($settings);$dialplan=new DialplanGeneration();$module->doDialplanHook($dialplan,'asterisk',500);
    deletedReloadCheck(count($module->prepared)===1,'One reload repeated the expensive prompt pass for every panic rule.');
    foreach([$first,$second] as $rule){deletedReloadCheck(isset(\SLS\MassNotify\LivePagingConfig::promptFiles($module->prepared[0])['panic_'.$rule['id']]),'Batched prompt preparation omitted a valid rule.');}
});
class SelectedLegacyAudienceNormalizer extends \FreePBX\modules\Slsmassnotifyserver {
    public function getConfiguredPjsipExtensionNumbers(){return ['1000','1001'];}
    public function getAllPjsipExtensions(){return [];}
    public function getAvailableTones(){return [];}
    public function getAvailablePiperVoices(){return [['path'=>self::PIPER_AMY_VOICE,'available'=>true],['path'=>self::PIPER_VOICE,'available'=>true]];}
}
$normalizer=(new ReflectionClass(SelectedLegacyAudienceNormalizer::class))->newInstanceWithoutConstructor();
$normalizeReflection=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
$legacyDefault=$normalizeReflection->getMethod('getDefaultSettings')->invoke($normalizer);
$legacyDefault=array_replace($legacyDefault,$legacySettings);$legacyDefault['public_pbx_host']='fixture.example.invalid';$legacyDefault['desktop_clients']=[];
reloadCase('protected selected legacy audience survives normalization after deletion',static function()use($normalizer,$normalizeReflection,$legacyDefault){
    $candidate=$legacyDefault;$candidate['enabled']='0';
    $candidate['announcement_groups'][]=['id'=>'grp_bbbbbbbbbbbb','name'=>'Unselected audience','extensions'=>['1002'],'desktop_clients'=>[]];
    $answer=$normalizeReflection->getMethod('normalizeSettings')->invoke($normalizer,$candidate,$legacyDefault);
    deletedReloadCheck(count($answer['announcement_groups'])===1&&$answer['announcement_groups'][0]['id']==='grp_aaaaaaaaaaaa'&&$answer['announcement_groups'][0]['extensions']===['1002'],'Read/unrelated save lost selected legacy identifiers or retained unselected stale data.');
});
foreach(['changed selector','changed audience','malformed source'] as $change){
    reloadCase('protected legacy retention refuses '.$change,static function()use($change,$normalizer,$normalizeReflection,$legacyDefault){
        $source=$legacyDefault;$candidate=$source;
        if($change==='changed selector'){$candidate['announcement_groups'][0]['extensions']=['1003'];}
        if($change==='changed audience'){$candidate['announcement_groups'][0]['name']='Changed user proposal';}
        if($change==='malformed source'){$source['announcement_groups'][0]['extensions']=['1002','1002'];$candidate=$source;}
        try{$normalizeReflection->getMethod('normalizeSettings')->invoke($normalizer,$candidate,$source);throw new LogicException('Changed or malformed source acquired protected stale-audience preservation.');}catch(InvalidArgumentException $expected){}
    });
}
reloadCase('unsourced intermediate normalization joins unchanged protected audience',static function()use($legacySettings){
    $module=new DeletedExtensionReload($legacySettings);$proposal=$legacySettings;$proposal['enabled']='0';$answer=$module->normalizeProposal($proposal);
    deletedReloadCheck(($answer['announcement_groups'][0]['extensions']??[])===['1002'],'An intermediate unrelated normalizer dropped the authenticated selected audience before persistence.');
    $proposal['announcement_groups'][0]['extensions']=['1003'];
    try{$module->normalizeProposal($proposal);throw new LogicException('A new user-proposed deleted ID was treated as protected prior data.');}catch(InvalidArgumentException $expected){}
});
$warnings=file_get_contents($reloadWarnings);
deletedReloadCheck($warnings!==''&&!str_contains($warnings,'private-fixture-marker')&&!str_contains($warnings,$panicRule['secret']),'Reload warning is absent or leaked configuration.');
if($reloadFailures){throw new RuntimeException(implode("\n",$reloadFailures));}
echo "Global reload: proven native deletion is nonfatal, saved permissions and strict SLL save/apply remain intact, no empty authorization or generic error waiver.\n";
