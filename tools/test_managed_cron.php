<?php
declare(strict_types=1);
require dirname(__DIR__).'/slsmassnotifyserver/ManagedCron.php';
use FreePBX\modules\SlsManagedCron;
$cases=json_decode(file_get_contents(__DIR__.'/fixtures/installer_cron_ownership.json'),true,512,JSON_THROW_ON_ERROR);
foreach ($cases as $case) {
    $actual='unrelated';
    try { if (SlsManagedCron::owns($case['line'],$case['account'])) {$actual='owned';} }
    catch (RuntimeException $error) {$actual='review';}
    if ($actual!==$case['classification']) {throw new RuntimeException('Cron ownership mismatch: '.json_encode($case).' actual='.$actual);}
}
foreach (['0 2 * * * /usr/bin/sha256sum /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh',
    "0 2 * * * /usr/bin/printf '%s' '/usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'",
    "0 2 * * * /usr/bin/printf '%s' ';' '/usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'",
    '# /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh'] as $line) {
    if(SlsManagedCron::owns($line,'asterisk')){throw new RuntimeException('An unrelated marker operand/comment was owned.');}
}
foreach (["* * * * * /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh 2 >&1",
    "* * * * * /usr/local/bin/sls_mass_notify/sls_mass_notify_update.sh '2'>&1"] as $line) {
    $rejected=false;
    try {SlsManagedCron::owns($line,'root');} catch(RuntimeException $error) {$rejected=true;}
    if(!$rejected){throw new RuntimeException('An actual numeric cron argument was consumed as a redirection descriptor.');}
}
echo count($cases)." shared cron ownership fixtures preserve operands and reject unknown SLL execution.\n";
