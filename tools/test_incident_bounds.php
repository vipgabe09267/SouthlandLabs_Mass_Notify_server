<?php
declare(strict_types=1);
// Intercept only the incident namespace so this regression can prove that
// durable records and summaries never require write access merely to read.
eval(<<<'PHP'
namespace SLS\MassNotify;
function fopen($path,$mode,$include=false,$context=null){
    if(($GLOBALS['sls_incident_fopen_target']??null)===$path){$GLOBALS['sls_incident_fopen_modes'][]=$mode;}
    if(($GLOBALS['sls_incident_fopen_hook_target']??null)===$path){
        $hook=$GLOBALS['sls_incident_fopen_hook'];
        unset($GLOBALS['sls_incident_fopen_hook_target'],$GLOBALS['sls_incident_fopen_hook']);
        $hook();
    }
    return $context===null?\fopen($path,$mode,$include):\fopen($path,$mode,$include,$context);
}
function stream_get_contents($stream,$length=-1,$offset=-1){
    if(($GLOBALS['sls_incident_read_hook_target']??null)===(\stream_get_meta_data($stream)['uri']??null)){
        $hook=$GLOBALS['sls_incident_read_hook'];
        unset($GLOBALS['sls_incident_read_hook_target'],$GLOBALS['sls_incident_read_hook']);
        $hook();
    }
    return \stream_get_contents($stream,$length,$offset);
}
PHP);
require_once dirname(__DIR__) . '/slsmassnotifyserver/IncidentService.php';
use SLS\MassNotify\IncidentStore;
use SLS\MassNotify\IncidentService;
use SLS\MassNotify\IncidentConfig;
function bounds_check(bool $condition, string $message): void { if (!$condition) { throw new RuntimeException($message); } }
$root=sys_get_temp_dir().'/sls-incident-bounds-'.bin2hex(random_bytes(8)); mkdir($root,0700);
register_shutdown_function(static function () use ($root): void {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $file) { $file->isDir()&&!$file->isLink()?rmdir($file->getPathname()):unlink($file->getPathname()); } rmdir($root);
});
class CountingIncidentStore extends IncidentStore
{
    public array $reads=[];
    public function read(string $id): ?array { $this->reads[]=$id; return parent::read($id); }
}
$directory=$root.'/records'; $store=new CountingIncidentStore($directory); $sent=[]; $now=1800000000;
$template=IncidentConfig::template(['id'=>'tpl_'.str_repeat('a',24),'name'=>'Fixture','title'=>'Fixture drill','message'=>'Fixture only','delivery'=>['desktop_clients'=>['fixture.desktop']]]);
$service=new IncidentService($store,static fn()=>$template,static fn(array $d):array=>$d,
    static function (...$args) use (&$sent):array { $sent[]=$args;return ['success'=>true,'job_id'=>'job_'.str_pad(dechex(count($sent)),32,'0',STR_PAD_LEFT)]; },static fn():array=>[],static fn():int=>$now);
$seed=$service->start(['template_id'=>$template['id'],'request_id'=>str_repeat('f',32),'is_test'=>true],['identity'=>'Fixture','source'=>'test']);
$seed=$store->read($seed['id']);
$seedPath=$directory.'/'.$seed['id'].'.json';$seedBytes=file_get_contents($seedPath);
$GLOBALS['sls_incident_fopen_target']=$seedPath;$GLOBALS['sls_incident_fopen_modes']=[];
$store->read($seed['id']);$store->metadata($seed['id']);
unset($GLOBALS['sls_incident_fopen_target']);
bounds_check($GLOBALS['sls_incident_fopen_modes']!==[]&&!array_diff($GLOBALS['sls_incident_fopen_modes'],['rb']),'Incident read paths requested write access.');
// A protected writer may atomically replace either file between the reader's
// lstat and fopen. Retry a fresh verified snapshot without using stale bytes.
foreach ([$seedPath,$directory.'/.'.$seed['id'].'.summary'] as $index=>$target) {
    $title='Concurrent snapshot '.($index+1);
    $GLOBALS['sls_incident_fopen_hook_target']=$target;
    $GLOBALS['sls_incident_fopen_hook']=static function()use($store,$seed,$title):void{
        $store->transaction($seed['id'],static function(array $record)use($title):array{$record['title']=$title;return $record;});
    };
    $snapshot=$store->metadata($seed['id']);
    bounds_check($snapshot['row']['title']===$title,'An atomic replacement returned an old or invalid incident snapshot.');
}
// Full-record readers (including concurrent workers and transaction prechecks)
// must also take a fresh verified snapshot after a protected atomic replacement.
foreach (['fopen','read'] as $stage) {
    $prefix=$stage==='fopen'?'sls_incident_fopen_hook':'sls_incident_read_hook';
    $title='Concurrent full record '.$stage;
    $GLOBALS[$prefix.'_target']=$seedPath;
    $GLOBALS[$prefix]=static function()use($store,$seed,$title):void{
        $store->transaction($seed['id'],static function(array $record)use($title):array{$record['title']=$title;return $record;});
    };
    $snapshot=$store->read($seed['id']);
    bounds_check($snapshot['title']===$title,'A full-record reader failed to recover a protected atomic replacement.');
}
// Repeated replacement remains a bounded, fail-closed read, with no stale data
// accepted and no unbounded loop under a continuously changing record.
$replacementCount=0;
$replaceAgain=static function()use(&$replaceAgain,&$replacementCount,$store,$seed,$seedPath):void{
    $replacementCount++;
    $store->transaction($seed['id'],static function(array $record)use(&$replacementCount):array{$record['title']='Repeated replacement '.$replacementCount;return $record;});
    $GLOBALS['sls_incident_read_hook_target']=$seedPath;
    $GLOBALS['sls_incident_read_hook']=$replaceAgain;
};
$GLOBALS['sls_incident_read_hook_target']=$seedPath;$GLOBALS['sls_incident_read_hook']=$replaceAgain;
$rejected=false;
try{$store->read($seed['id']);}catch(RuntimeException $expected){$rejected=true;}
unset($GLOBALS['sls_incident_read_hook_target'],$GLOBALS['sls_incident_read_hook']);
bounds_check($rejected&&$replacementCount===2,'Continuously replaced incident reads were unbounded or returned stale history.');
file_put_contents($seedPath,$seedBytes);
chmod($seedPath,0644);$rejected=false;try{$store->read($seed['id']);}catch(RuntimeException $expected){$rejected=true;}chmod($seedPath,0600);
bounds_check($rejected,'World-readable incident history was accepted.');
$damaged=json_decode($seedBytes,true,64,JSON_THROW_ON_ERROR);$requestKey=array_key_first($damaged['operations']);$damaged['operations'][$requestKey]['actor']['identity']=[];
file_put_contents($seedPath,json_encode($damaged,JSON_THROW_ON_ERROR));chmod($seedPath,0600);$rejected=false;
try{$store->read($seed['id']);}catch(RuntimeException $expected){$rejected=true;}file_put_contents($seedPath,$seedBytes);chmod($seedPath,0600);
bounds_check($rejected,'Malformed nested incident history escaped durable-record validation.');
$damaged=json_decode($seedBytes,true,64,JSON_THROW_ON_ERROR);$damaged['unexpected_root']='not part of schema 1';
file_put_contents($seedPath,json_encode($damaged,JSON_THROW_ON_ERROR));chmod($seedPath,0600);$rejected=false;
try{$store->read($seed['id']);}catch(RuntimeException $expected){$rejected=true;}file_put_contents($seedPath,$seedBytes);chmod($seedPath,0600);
bounds_check($rejected,'Unknown incident root data escaped durable-record validation.');
$damaged=json_decode($seedBytes,true,64,JSON_THROW_ON_ERROR);$damaged['template']['name']=' Fixture ';
file_put_contents($seedPath,json_encode($damaged,JSON_THROW_ON_ERROR));chmod($seedPath,0600);$rejected=false;
try{$store->read($seed['id']);}catch(RuntimeException $expected){$rejected=true;}file_put_contents($seedPath,$seedBytes);chmod($seedPath,0600);
bounds_check($rejected,'A noncanonical frozen incident template escaped durable-record validation.');
$lockPath=$directory.'/'.$seed['id'].'.lock';file_put_contents($lockPath,'x');chmod($lockPath,0600);$rejected=false;
try{$store->transaction($seed['id'],static fn(array $record):array=>$record);}catch(RuntimeException $expected){$rejected=true;}file_put_contents($lockPath,'');
bounds_check($rejected,'A nonempty incident lock file was accepted.');
// The upper record-count boundary plus eight near-limit records (32 MiB). Full
// reads are instrumented, proving warm list/worker cost does not scale to 8 GiB.
foreach (glob($directory.'/*') as $path) { unlink($path); }
foreach (glob($directory.'/.*summary') as $path) { unlink($path); }
$ids=[];
for ($i=0;$i<2000;$i++) {
    $id='inc_'.str_pad(dechex($i+1),32,'0',STR_PAD_LEFT);$ids[]=$id;
    $record=$seed;$record['id']=$id;$record['state']='closed';$record['operations']=[];$record['timeline']=[];
    if ($i<8) { $record['timeline']=[['at'=>$record['updated_at'],'kind'=>'fixture_padding',
        'actor'=>['identity'=>'Fixture','source'=>'test'],'details'=>['padding'=>str_repeat('p',3900000)]]]; }
    if ($i===1999) { $record['state']='planned';$record['planned_at']=gmdate('c',$now-30);$record['opened_at']=''; }
    $raw=json_encode(['_storage_revision'=>bin2hex(random_bytes(16))]+$record,JSON_THROW_ON_ERROR);
    file_put_contents($directory.'/'.$id.'.json',$raw);chmod($directory.'/'.$id.'.json',0600);
    $store->metadata($id);
}
$store->reads=[];$cursor='';$seen=[];$started=microtime(true);
do {
    $page=$service->listing(200,$cursor);bounds_check($page['total']===2000,'Maximum history total changed.');
    foreach ($page['incidents'] as $row) { bounds_check(!isset($seen[$row['id']]),'History cursor repeated a row.');$seen[$row['id']]=true; }
    $cursor=$page['next_cursor'];
} while ($cursor!=='');
bounds_check(count($seen)===2000,'Keyset pagination omitted maximum-capacity records.');
bounds_check($store->reads===[],'Warm history listing read complete incident bodies.');
$elapsed=microtime(true)-$started;
$store->reads=[];$before=count($sent);$work=$service->process();
bounds_check($work['success']&&$work['processed']===1&&count($sent)===$before+1,'Late-position scheduled drill starved behind large closed histories.');
bounds_check(array_unique($store->reads)===[$ids[1999]],'Worker loaded unrelated closed full records.');
// Missing/corrupt summaries rebuild one bounded full record, then go warm.
$id=$ids[10];$cache=$directory.'/.'.$id.'.summary';unlink($cache);$store->reads=[];$store->metadata($id);
bounds_check(count($store->reads)===1,'Missing cache did not rebuild exactly one record.');
file_put_contents($cache,'{"damaged":');$store->reads=[];$store->metadata($id);
bounds_check(count($store->reads)===1,'Damaged summary was accepted or not repaired.');
$store->reads=[];$store->metadata($id);bounds_check(!$store->reads,'Repaired summary did not stay warm.');
// Revision binding catches same-inode/same-length writes even when stat times
// cannot distinguish rapid replacement on filesystems exposing only seconds.
$path=$directory.'/'.$id.'.json';$beforeStat=stat($path);$raw=json_decode(file_get_contents($path),true);$raw['_storage_revision']=bin2hex(random_bytes(16));$raw['title']='Changed title';
file_put_contents($path,json_encode($raw));touch($path,$beforeStat['mtime']);$store->reads=[];$metadata=$store->metadata($id);
bounds_check(count($store->reads)===1&&$metadata['row']['title']==='Changed title','Stale summary survived storage revision change.');
// Legacy records are upgraded under their incident lock without altering logical
// history or triggering the sender, so cold migration makes durable progress.
$logical=$store->read($id);file_put_contents($path,json_encode($logical));$before=count($sent);$store->metadata($id);$after=$store->read($id);
bounds_check($logical===$after&&count($sent)===$before,'Legacy summary migration altered history or sent an alert.');
$store->reads=[];$store->metadata($id);bounds_check(!$store->reads,'Legacy migration did not produce a revision-bound cache.');
// Cache publication failure cannot alter the successful durable claim outcome.
$bad=$directory.'/.'.$ids[11].'.summary';unlink($bad);symlink($root.'/outside',$bad);
$record=$store->transaction($ids[11],static function(array $r):array{$r['title']='Durable despite cache';return $r;});
bounds_check($store->read($ids[11])['title']==='Durable despite cache','Optional cache failure lost durable incident mutation.');
try {$store->metadata($ids[11]);throw new LogicException('Unsafe summary link accepted.');}catch(RuntimeException $expected){}
echo 'Incident 2000-record compact history pagination, due-only worker, cache revision/migration and durable-claim isolation passed; ten pages '.number_format($elapsed,3).'s.'.PHP_EOL;
