<?php
declare(strict_types=1);
if (getenv('SLS_TEST_NAMESPACE')!=='entered') { throw new RuntimeException('Use the unchanged isolated wrapper.'); }
require dirname(__DIR__).'/slsmassnotifyserver/OperatorLoginRate.php';
use SLS\MassNotify\OperatorLoginRate as Rate;
$root=sys_get_temp_dir().'/sls-registry-notice-'.bin2hex(random_bytes(8));mkdir($root,0700);
$path=$root.'/failures.json';$now=100000;$fullRecoverySignalled=false;$checks=[];
try {
    for ($i=0;$i<512;$i++) {
        $ip='2001:db8::'.dechex($i+1);$grant=Rate::begin($path,$ip,$now);
        Rate::finish($path,$ip,$grant['reservation'],true,$now);
    }
    $before=file_get_contents($path);
    try { Rate::recovered($path,'2001:db8:1::1',$now); }
    catch (RuntimeException $error) { $fullRecoverySignalled=$error->getMessage()==='operator_failure_storage_full'; }
    $checks['new_address_full_registry_signals_notice']=$fullRecoverySignalled;
    $checks['capacity_refusal_preserves_other_failures']=file_get_contents($path)===$before;
    Rate::recovered($path,'2001:db8::1',$now);
    $existing=Rate::begin($path,'2001:db8::1',$now);
    $checks['existing_address_verified_recovery_still_admits']=$existing['retry_after']===0;
    Rate::finish($path,'2001:db8::1',$existing['reservation'],false,$now);
    // With space, a valid recovery at a new address needs no special row.
    Rate::recovered($path,'2001:db8:1::1',$now);
    $fresh=Rate::begin($path,'2001:db8:1::1',$now);
    $checks['new_address_with_capacity_still_admits']=$fresh['retry_after']===0;
    Rate::finish($path,'2001:db8:1::1',$fresh['reservation'],false,$now);
    echo 'SLS_REGISTRY_RECOVERY_NOTICE '.json_encode($checks,JSON_THROW_ON_ERROR)."\n";
    if (in_array(false,$checks,true)) { throw new RuntimeException('Capacity-limited recovery falsely reports address unlock or changes existing protection.'); }
} finally { foreach (glob($root.'/*') as $path) { unlink($path); }rmdir($root); }
