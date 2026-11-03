<?php
declare(strict_types=1);
namespace FreePBX\modules {
    function exec($command, &$output, &$code=null): void {
        if (!empty($GLOBALS['cron_fixture']['actual_process'])) {\exec($command,$output,$code);return;}
        $read=!empty($GLOBALS['cron_fixture']['reads'])?array_shift($GLOBALS['cron_fixture']['reads']):$GLOBALS['cron_fixture'];
        $code=$read['code'];$output=$read['lines'];
        if(strpos($command,'/usr/bin/base64')!==false){$output=[base64_encode(implode("\n",$output).($output?"\n":""))];}
    }
    function posix_geteuid(): int {return \posix_geteuid();}
    function posix_getpwuid($uid): array {return ['name'=>'private-fixture'];}
}
namespace {
    if (!interface_exists('BMO')) {interface BMO {}}
    require dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
    $reflection=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
    $sourcePath=$reflection->getFileName();
    if(!is_string($sourcePath)||$sourcePath===''){throw new \RuntimeException('Module source path is unavailable.');}
    $source=file($sourcePath);
    if(!is_array($source)){throw new \RuntimeException('Module source is unreadable.');}
    $fixtureProgram=tempnam(sys_get_temp_dir(),'sls-cron-read-');
    file_put_contents($fixtureProgram,'<?php $file=getenv("SLS_CRON_READ_FILE");fwrite(STDOUT,$file?file_get_contents($file):base64_decode(getenv("SLS_CRON_READ_BYTES")));exit((int)getenv("SLS_CRON_READ_STATUS"));');
    register_shutdown_function(static function()use($fixtureProgram){unlink($fixtureProgram);});
    $body='';
    foreach(['unlinkNamedFileIfIdentity','slsCronLine','updateManagedUserCron','removeLegacyNwsCronJob','readNativeUserCrontab','installNativeUserCrontab']as$name){
        $method=$reflection->getMethod($name);$methodLines=array_slice($source,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1);
        if(!$methodLines){throw new \RuntimeException('Cron helper source is missing: '.$name);}
        $methodBody=implode('',$methodLines);
        if($name==='readNativeUserCrontab'){$methodBody=str_replace('/usr/bin/crontab -l','/usr/bin/php '.$fixtureProgram,$methodBody);}
        $body.=$methodBody;
    }
    eval('namespace FreePBX\\modules;class CronFixture {public $commands=[];public $saved="";private function withNativeCronLock($operation,$account="asterisk"){return $operation();}private function runCommand($command,$timeout=120){$this->commands[]=$command;$this->saved=file_get_contents(trim(substr($command,strlen("/usr/bin/crontab ")),"\'"));$GLOBALS["cron_fixture"]["lines"]=$this->saved==="\n"?[]:explode("\n",rtrim($this->saved,"\n"));if(!empty($GLOBALS["cron_fixture"]["actual_process"])){putenv("SLS_CRON_READ_BYTES=".base64_encode($this->saved));}return true;}public function read(){return $this->readNativeUserCrontab();}public function clean(){return $this->removeLegacyNwsCronJob();}'.$body.'}');
    foreach ([['code'=>2,'lines'=>['* * * * * /usr/local/bin/nws_weather_alert.sh']],
        ['code'=>124,'lines'=>[]],['code'=>1,'lines'=>['permission denied']]] as $failed) {
        $GLOBALS['cron_fixture']=$failed;$fixture=new \FreePBX\modules\CronFixture;$rejected=false;
        try {$fixture->clean();}catch(\RuntimeException $error){$rejected=true;}
        if(!$rejected||$fixture->commands!==[]){throw new \RuntimeException('A failed crontab read reached replacement or was silently accepted.');}
    }
    $GLOBALS['cron_fixture']=['code'=>1,'lines'=>['no crontab for private-fixture']];
    $fixture=new \FreePBX\modules\CronFixture;$fixture->clean();
    if($fixture->commands!==[]){throw new \RuntimeException('A genuinely empty crontab was changed by legacy cleanup.');}
    $unrelated='7 * * * * /usr/local/bin/private-unrelated-job';
    $GLOBALS['cron_fixture']=['code'=>0,'lines'=>[$unrelated,'* * * * * /usr/local/bin/nws_weather_alert.sh']];
    $fixture=new \FreePBX\modules\CronFixture;$fixture->clean();
    if(count($fixture->commands)!==1||$fixture->saved!==$unrelated."\n"){throw new \RuntimeException('Verified legacy cleanup altered an unrelated cron entry.');}
    $operands=['# preserve /usr/local/bin/nws_weather_alert.sh notes',
        '0 3 * * * /usr/bin/sha256sum /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'];
    $GLOBALS['cron_fixture']=['code'=>0,'lines'=>array_merge($operands,['* * * * * /usr/local/bin/nws_weather_alert.sh'])];
    $fixture=new \FreePBX\modules\CronFixture;$fixture->clean();
    if($fixture->saved!==implode("\n",$operands)."\n"){throw new \RuntimeException('Cron cleanup removed an unrelated comment or checksum operand.');}
    $GLOBALS['cron_fixture']=['code'=>0,'lines'=>['* * * * * /usr/local/bin/sls_mass_notify/unreviewed.php']];
    $fixture=new \FreePBX\modules\CronFixture;$rejected=false;
    try{$fixture->clean();}catch(\RuntimeException $error){$rejected=true;}
    if(!$rejected||$fixture->commands!==[]){throw new \RuntimeException('Unknown SLL execution reached a cron write.');}
    $initial=[$unrelated,'* * * * * /usr/local/bin/nws_weather_alert.sh'];
    $changed=array_merge($initial,['11 3 * * * /fixture/other-administrator']);
    $GLOBALS['cron_fixture']=['code'=>0,'lines'=>$changed,'reads'=>[['code'=>0,'lines'=>$initial],['code'=>0,'lines'=>$changed]]];
    $fixture=new \FreePBX\modules\CronFixture;$rejected=false;
    try{$fixture->clean();}catch(\RuntimeException $error){$rejected=true;}
    if(!$rejected||$fixture->commands!==[]){throw new \RuntimeException('Concurrent cron changes were overwritten.');}
    $GLOBALS['cron_fixture']=['code'=>0,'lines'=>$initial,'reads'=>[['code'=>0,'lines'=>$initial],['code'=>0,'lines'=>$initial],['code'=>2,'lines'=>[]]]];
    $fixture=new \FreePBX\modules\CronFixture;$rejected=false;
    try{$fixture->clean();}catch(\RuntimeException $error){$rejected=true;}
    if(!$rejected||count($fixture->commands)!==1){throw new \RuntimeException('A failed cron readback was accepted or triggered snapshot restoration.');}
    $raw="# preserve trailing whitespace  \t\n\n0 2 * * * /usr/bin/echo literal\\ \n";
    $legacy="* * * * * /usr/local/bin/nws_weather_alert.sh\n";
    $GLOBALS['cron_fixture']=['actual_process'=>true];
    putenv('SLS_CRON_READ_STATUS=0');putenv('SLS_CRON_READ_BYTES='.base64_encode($raw.$legacy));
    $fixture=new \FreePBX\modules\CronFixture;
    if(implode("\n",$fixture->read())."\n"!==$raw.$legacy){throw new \RuntimeException('Real PHP exec trimmed original crontab whitespace or blank lines.');}
    $fixture->clean();
    if($fixture->saved!==$raw){throw new \RuntimeException('Native cron merge changed unrelated trailing whitespace or blank lines.');}
    putenv('SLS_CRON_READ_BYTES='.base64_encode($legacy));$fixture=new \FreePBX\modules\CronFixture;$fixture->clean();
    if($fixture->saved!==''){throw new \RuntimeException('Empty managed crontab replacement was not exactly empty bytes.');}
    $largeInput=tempnam(sys_get_temp_dir(),'sls-cron-large-');
    register_shutdown_function(static function()use($largeInput){unlink($largeInput);});
    putenv('SLS_CRON_READ_FILE='.$largeInput);
    foreach([str_repeat("* * * * * /fixture/unrelated-job\n",40000),"0 2 * * * /fixture/missing-final-newline"] as $unsafe){
        file_put_contents($largeInput,$unsafe);$fixture=new \FreePBX\modules\CronFixture;$rejected=false;
        try{$fixture->read();}catch(\RuntimeException $error){$rejected=true;}
        if(!$rejected||$fixture->commands!==[]){throw new \RuntimeException('Oversized or incomplete raw cron read was accepted.');}
    }
    putenv('SLS_CRON_READ_BYTES');putenv('SLS_CRON_READ_STATUS');putenv('SLS_CRON_READ_FILE');
    echo "Native legacy cron cleanup rejects partial/error/timeout reads and preserves an absent user crontab; no cron command executed.\n";
}
