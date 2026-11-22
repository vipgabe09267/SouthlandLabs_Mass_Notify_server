<?php
declare(strict_types=1);
require dirname(__DIR__).'/slsmassnotifyserver/AmiUserOwnership.php';
use SLS\MassNotify\AmiUserOwnership;

$db = new class('sqlite::memory:') extends PDO {
    public function prepare(string $query, array $options = []): PDOStatement|false {
        if ($query === 'SHOW TABLES LIKE ?') { $query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"; }
        return parent::prepare(preg_replace('/BINARY (`?[a-z_]+`?)/', '$1 COLLATE BINARY', $query), $options);
    }
}; $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE manager (manager_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT COLLATE NOCASE, secret TEXT COLLATE NOCASE, deny TEXT, permit TEXT, `read` TEXT, `write` TEXT, writetimeout INTEGER)');
$insert = $db->prepare('INSERT INTO manager (name,secret,deny,permit,`read`,`write`,writetimeout) VALUES (?, ?, ?, ?, ?, ?, ?)');
$base = ['name'=>'slsmassnotify', 'secret'=>'private-fixture-only', 'deny'=>'0.0.0.0/0.0.0.0&::/0',
    'permit'=>'127.0.0.1/255.255.255.255&::1/128', 'read'=>'system,call,originate,reporting',
    'write'=>'system,call,originate,reporting', 'writetimeout'=>1000];
$proof = hash('sha256', $base['secret']); $checks = 0;
function check($condition, string $message): void { global $checks; $checks++; if (!$condition) throw new RuntimeException($message); }
check(AmiUserOwnership::matches($base, $base['name'], $proof), 'Dedicated SLS account not recognized.');
$legacy=array_replace($base,['deny'=>'0.0.0.0/0.0.0.0','permit'=>'127.0.0.1/255.255.255.255',
    'read'=>'system,call,originate','write'=>'system,call,originate']);
check(AmiUserOwnership::matches($legacy,$legacy['name'],$proof),'Authenticated pre-0.1.5 SLS AMI profile was not recognized for migration.');
foreach ([['secret'=>'unrelated'], ['permit'=>'0.0.0.0/0'], ['permit'=>'127.0.0.1/24'], ['permit'=>[]], ['permit'=>'::1/128', 'deny'=>'0.0.0.0/0.0.0.0'], ['deny'=>''], ['deny'=>[]], ['deny'=>$base['deny'].'&127.0.0.1/32'],
    ['read'=>'system,call'], ['write'=>'system,call,originate,reporting,command'], ['writetimeout'=>2000], ['name'=>'other']] as $change) {
    check(!AmiUserOwnership::matches(array_replace($base, $change), $base['name'], $proof), 'Unproven or broadly permitted account was adopted.');
}
foreach (['slsmassnotify','sls_mass_notify','nws_push','Admin','remote','site_policy'] as $name) {
    $row = $base; $row['name'] = $name;
    if ($name === 'nws_push') { $row['secret'] = 'another-integration'; }
    if ($name === 'remote') { $row['permit'] = '192.0.2.0/24'; }
    if ($name === 'site_policy') { $row['deny'] .= '&127.0.0.1/32'; }
    $insert->execute(array_values($row));
}
$removed = AmiUserOwnership::remove($db, ['slsmassnotify',[],'sls_mass_notify','slsmassnotify','nws_push','Admin','remote','site_policy','absent'], $proof, 'admin');
check($removed === ['slsmassnotify','sls_mass_notify'], 'Removal did not preserve unrelated and administrative accounts.');
check($db->query('SELECT name FROM manager ORDER BY name')->fetchAll(PDO::FETCH_COLUMN) === ['Admin','nws_push','remote','site_policy'], 'Unrelated manager accounts changed.');
check(AmiUserOwnership::remove($db, ['slsmassnotify','sls_mass_notify'], $proof, 'admin') === [], 'Repeated removal was not harmless.');

// A concurrent credential change after lookup must defeat the conditional delete.
$row = $base; $row['name'] = 'changed'; $insert->execute(array_values($row));
$adapter = new class($db) {
    public function __construct(private PDO $db) {}
    public function prepare(string $sql) {
        if (!str_starts_with($sql, 'DELETE')) return $this->db->prepare($sql);
        return new class($this->db, $sql) {
            private PDOStatement $statement;
            public function __construct(private PDO $db, string $sql) { $this->statement = $db->prepare($sql); }
            public function execute(array $arguments) { $this->db->exec("UPDATE manager SET secret=UPPER(secret) WHERE name='changed'");
                $this->db->exec("UPDATE manager SET manager_id=1000 WHERE name='replaced' AND manager_id<>1000");
                return $this->statement->execute($arguments); }
            public function rowCount(): int { return $this->statement->rowCount(); }
        };
    }
};
$row['name'] = 'replaced'; $insert->execute(array_values($row));
check(AmiUserOwnership::remove($adapter, ['replaced'], $proof, 'admin') === [], 'Removal deleted the replacement native account with a different ID.');
$db->exec("UPDATE manager SET secret='private-fixture-only' WHERE name='changed'");
check(AmiUserOwnership::remove($adapter, ['changed'], $proof, 'admin') === [], 'Concurrent manager edit was deleted.');
check($db->query("SELECT secret FROM manager WHERE name='changed'")->fetchColumn() === strtoupper($base['secret']), 'Concurrent credential change was lost.');
$file = "; BEGIN SLS Mass Notifications AMI\n[slsmassnotify]\nsecret = private-fixture-only\ndeny = 0.0.0.0/0.0.0.0\ndeny = ::/0\npermit = 127.0.0.1/255.255.255.255\npermit = ::1/128\nread = system,call,originate,reporting\nwrite = system,call,originate,reporting\n; END SLS Mass Notifications AMI\n";
check(AmiUserOwnership::fileAccount($file, $base['name'], $proof) === $base['name'], 'File fallback account was omitted.');
$oldFile = str_replace(['; BEGIN SLS Mass Notifications AMI','; END SLS Mass Notifications AMI',
    "deny = ::/0\n","permit = ::1/128\n",',reporting'],
    [';-- BEGIN SLS Mass Notifications AMI --',';-- END SLS Mass Notifications AMI --','','',''], $file);
check(AmiUserOwnership::fileAccount(str_replace("\n", "\r\n", $oldFile), $base['name'], $proof) === $base['name'],
    'The historical IPv4-only file fallback and legacy markers were not recognized.');
check(AmiUserOwnership::fileAccount("[operator]\n", $base['name'], $proof) === null, 'Unmarked unrelated account was adopted.');
foreach ([str_replace('read =', "deny = 127.0.0.1/32\nread =", $file), $file.$file,
          str_replace("deny = ::/0\npermit = 127.0.0.1/255.255.255.255","permit = 127.0.0.1/255.255.255.255\ndeny = ::/0",$file),
          $file."[SLSMASSNOTIFY](+)\n", str_replace('private-fixture-only','other',$file)] as $unsafe) {
    $refused = false;
    try { AmiUserOwnership::fileAccount($unsafe, $base['name'], $proof); } catch (RuntimeException $e) { $refused = true; }
    check($refused, 'Unproven, custom or ambiguous managed file policy was claimed.');
}
echo "AMI ownership: {$checks} credential, loopback, administrator, legacy, idempotency and concurrent-edit checks passed; no PBX database used.\n";
