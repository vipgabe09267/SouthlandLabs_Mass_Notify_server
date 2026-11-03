<?php
declare(strict_types=1);
namespace SlsNativeCronLockFixture {
    function posix_getpwuid($uid) { return ['name'=>'asterisk']; }
}
namespace {
    $parent=getenv('SLS_TEST_PARENT_IPC_NS');
    if(!$parent||readlink('/proc/self/ns/ipc')===$parent){throw new RuntimeException('Real semaphore fixtures require a distinct disposable IPC namespace.');}
    if(!isset($argv[1])) {
        $modes=['--fixture'];
        if(is_file('/var/www/html/admin/libraries/Composer/vendor/autoload.php')&&is_file('/var/www/html/admin/libraries/BMO/Cron.class.php')){$modes[]='--native';}
        foreach($modes as $mode){
            $process=proc_open([PHP_BINARY,__FILE__,$mode],[0=>['file','/dev/null','r'],1=>STDOUT,2=>STDERR],$pipes);
            if(!is_resource($process)||proc_close($process)!==0){throw new RuntimeException('Cron semaphore mode failed: '.$mode);}
        }
        exit(0);
    }
    if(!in_array($argv[1],['--fixture','--native'],true)){throw new RuntimeException('Unknown native lock fixture mode.');}
    $bootstrap=$argv[1]==='--native'
        ? "require '/var/www/html/admin/libraries/Composer/vendor/autoload.php'; require '/var/www/html/admin/libraries/BMO/Cron.class.php';"
        : 'require '.var_export(__DIR__.'/fixtures/native_cron_semaphore.php',true).';';
    eval($bootstrap);
    interface BMO {}
    require dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
    $method=new ReflectionMethod(FreePBX\modules\Slsmassnotifyserver::class,'withNativeCronLock');
    $source=file($method->getFileName());
    $body=implode('',array_slice($source,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));
    eval('namespace SlsNativeCronLockFixture;class Module {public function apply($operation){return $this->withNativeCronLock($operation);}'.$body.'}');
    // Hold the exact lock created by the installed native FreePBX Cron writer.
    // Only getLock() is called; no crontab is read or executed.
    $holder=<<<'CHILD'
$reflection=new ReflectionClass(FreePBX\Cron::class);$cron=$reflection->newInstanceWithoutConstructor();
$user=$reflection->getProperty('user');$user->setAccessible(true);$user->setValue($cron,'asterisk');
$getLock=$reflection->getMethod('getLock');$getLock->setAccessible(true);$lock=$getLock->invoke($cron);
$lock->acquire(true);echo "ready\n";flush();fgets(STDIN);$lock->release();
CHILD;
    $process=proc_open([PHP_BINARY,'-r',$bootstrap."\n".$holder],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($process)){throw new RuntimeException('Cannot start native semaphore fixture.');}
    $calls=0;$rejected=false;$module=new SlsNativeCronLockFixture\Module();
    try {
        stream_set_timeout($pipes[1],5);
        if(fgets($pipes[1])!=="ready\n"){throw new RuntimeException('Native semaphore did not become ready: '.stream_get_contents($pipes[2]));}
        $started=microtime(true);
        try{$module->apply(function()use(&$calls){$calls++;});}catch(RuntimeException $error){$rejected=strpos($error->getMessage(),'busy')!==false;}
        if(!$rejected||$calls!==0||microtime(true)-$started>7){throw new RuntimeException('A competing native writer did not prevent a bounded cron mutation.');}
    } finally {
        fwrite($pipes[0],"release\n");fclose($pipes[0]);fclose($pipes[1]);$stderr=stream_get_contents($pipes[2]);fclose($pipes[2]);
        $status=proc_close($process);
    }
    if($status!==0){throw new RuntimeException('Native semaphore fixture failed: '.$stderr);}
    $module->apply(function()use(&$calls){$calls++;});
    if($calls!==1){throw new RuntimeException('A released native lock did not admit exactly one mutation.');}
    try{$module->apply(function(){throw new RuntimeException('fixture operation failure');});}catch(RuntimeException $error){}
    $module->apply(function()use(&$calls){$calls++;});
    if($calls!==2){throw new RuntimeException('A failed mutation retained its native semaphore.');}
    echo ($argv[1]==='--native'?'Installed native':'Pinned inert')." FreePBX cron semaphore blocks mutations, times out, and releases on success/failure in isolated IPC.\n";
}
