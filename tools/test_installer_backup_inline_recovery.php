<?php
/** Exercise the actual installer fallback used when the restored old class lacks the new method. */
if (getenv('SLS_TEST_NAMESPACE') !== 'entered') { throw new RuntimeException('Use the official isolated fixture runner'); }
final class InlineNativeBackup {
    private $database;
    public function __construct() {
        $this->database = new PDO('sqlite::memory:');
        $this->database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->database->exec('CREATE TABLE selections(job TEXT,name TEXT,value TEXT,PRIMARY KEY(job,name))');
    }
    public function getAll($id) {
        if ($id === 'backupList') { return ['job' => ['name' => 'Existing job']]; }
        $query = $this->database->prepare('SELECT name,value FROM selections WHERE job=?');
        $query->execute([$id]); return $query->fetchAll(PDO::FETCH_KEY_PAIR);
    }
    public function setConfig($key, $value, $id) {
        $query = $this->database->prepare('INSERT OR REPLACE INTO selections VALUES(?,?,?)');
        $query->execute([$id, $key, $value]);
    }
    public function delConfig($key, $id) {
        $query = $this->database->prepare('DELETE FROM selections WHERE job=? AND name=?');
        $query->execute([$id, $key]);
    }
}
class FreePBX {
    public static $backup;
    public static function Create() { return (object)['Backup' => self::$backup]; }
}
$source = file_get_contents(dirname(__DIR__) . '/tools/install_release.sh');
$start = strpos($source, 'if ($data["backup_enrollment"]) {');
if ($start === false) { throw new RuntimeException('Actual installer backup restoration block missing'); }
$body = ''; $depth = 0; $begun = false;
foreach (token_get_all('<?php ' . substr($source, $start)) as $token) {
    if (is_array($token)) { if ($token[0] !== T_OPEN_TAG) { $body .= $token[1]; } continue; }
    $body .= $token;
    if ($token === '{') { $depth++; $begun = true; }
    if ($token === '}' && --$depth === 0 && $begun) { break; }
}
foreach ([[false, null, '1', false, null], [true, '0', '1', true, '0'],
          [false, null, 'administrator-edit', true, 'administrator-edit'], [true, 'yes', '1', true, '1']]
         as [$present, $baseline, $current, $retained, $expected]) {
    FreePBX::$backup = new InlineNativeBackup();
    FreePBX::$backup->setConfig('core', '1', 'modules_job');
    FreePBX::$backup->setConfig('unrelated', 'preserved', 'modules_job');
    FreePBX::$backup->setConfig('slsmassnotifyserver', $current, 'modules_job');
    $data = ['backup_enrollment' => [['job' => 'job', 'present' => $present, 'value' => $baseline]]];
    eval($body);
    $selection = FreePBX::$backup->getAll('modules_job');
    if (array_key_exists('slsmassnotifyserver', $selection) !== $retained
        || $retained && $selection['slsmassnotifyserver'] !== $expected) {
        throw new RuntimeException('Legacy-class installer recovery failed to restore the exact persisted enrollment');
    }
    if ($selection['core'] !== '1' || $selection['unrelated'] !== 'preserved') {
        throw new RuntimeException('Installer recovery changed unrelated native selections');
    }
}
echo "Legacy-class installer backup fallback preserves persisted scalars and independent edits.\n";
