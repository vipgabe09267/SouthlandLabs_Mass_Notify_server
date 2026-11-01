<?php
declare(strict_types=1);
namespace SLS\MassNotify { function time(): int { return $GLOBALS['sls_lookup_clock']; } }
namespace {
if (getenv('SLS_TEST_NAMESPACE')!=='entered') { throw new RuntimeException('Use the unchanged isolated wrapper.'); }
require dirname(__DIR__).'/slsmassnotifyserver/OperatorAccess.php';
use SLS\MassNotify\{OperatorAccess,ApiSecurity};
class FreePBX {}
class ampuser {
    public static array $row=[];
    public function __construct(string $username,string $source) {}
    public function getAmpUser(string $username): array {
        $GLOBALS['sls_lookup_count']++;
        $GLOBALS['sls_lookup_clock']+=$GLOBALS['sls_lookup_delay'];
        return self::$row;
    }
}
$base=100000;$id='api_'.str_repeat('a',24);$failures=[];
ampuser::$row=['id'=>42,'username'=>'synthetic-operator','mode'=>'database',
    'password_sha1'=>str_repeat('b',40),'sections'=>['slsmassnotifyserver_operations']];
foreach (['unchanged'=>[0,0,$base+5], 'expiry_during_lookup'=>[0,10,$base+5],
    'expired_before_lookup'=>[6,0,$base+5], 'unlimited_lookup'=>[0,10,0]] as $name=>[$initial,$delay,$expiry]) {
    $GLOBALS['sls_lookup_clock']=$base+$initial;$GLOBALS['sls_lookup_delay']=$delay;$GLOBALS['sls_lookup_count']=0;
    $account=['id'=>$id,'username'=>ampuser::$row['username'],'source'=>'database','name'=>'Synthetic operator',
        'role'=>'sender','enabled'=>true,'expires_at'=>$expiry,'identity'=>OperatorAccess::identity(ampuser::$row),
        'personal_members'=>['extensions'=>['1001']]];
    $settings=['operator_access'=>['enabled'=>true,'accounts'=>[$account]],'control_api'=>['enabled'=>true,'credentials'=>[]]];
    $principal=ApiSecurity::currentCredential($settings,$id);
    echo 'SLS_OPERATOR_LOOKUP_EXPIRY '.json_encode(['case'=>$name,'clock_after'=>$GLOBALS['sls_lookup_clock'],
        'expires_at'=>$expiry,'lookup_calls'=>$GLOBALS['sls_lookup_count'],'returned_principal'=>$principal!==null,
        'principal_active_at_return'=>$principal!==null&&OperatorAccess::activeAccount($principal)],JSON_THROW_ON_ERROR)."\n";
    $expected=in_array($name,['unchanged','unlimited_lookup'],true);
    if (($principal!==null)!==$expected) { $failures[]=$name; }
    if ($name==='expired_before_lookup' && $GLOBALS['sls_lookup_count']!==0) { throw new RuntimeException('Expired account still reached PBX lookup.'); }
}
if ($failures) { throw new RuntimeException('Current credential returned expired local operator after PBX identity lookup: '.implode(',',$failures)); }
}
