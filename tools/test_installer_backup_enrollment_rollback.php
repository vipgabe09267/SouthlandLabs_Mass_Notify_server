<?php
/** Real private PDO storage at the native Backup API boundary; no PBX bootstrap. */
interface BMO {}
require_once dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
$runtime=posix_getpwnam('asterisk');
if(posix_geteuid()===0){if(!posix_setgid($runtime['gid'])||!posix_setuid($runtime['uid'])){throw new RuntimeException('Cannot enter private runtime account');}}
function checkEnrollment($condition,$message){if(!$condition){throw new RuntimeException($message);}}
final class PersistedBackupSelection {
    private $database;
    public function __construct(){
        $this->database=new PDO('sqlite::memory:');$this->database->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
        $this->database->exec('CREATE TABLE selections (job TEXT, name TEXT, value TEXT, PRIMARY KEY(job,name))');
    }
    public function getAll($id){
        if($id==='backupList'){return ['job'=>['name'=>'Existing native job']];}
        $query=$this->database->prepare('SELECT name,value FROM selections WHERE job=?');$query->execute([$id]);return $query->fetchAll(PDO::FETCH_KEY_PAIR);
    }
    public function setConfig($name,$value,$job){$query=$this->database->prepare('INSERT OR REPLACE INTO selections VALUES(?,?,?)');$query->execute([$job,$name,$value]);}
    public function delConfig($name,$job){$query=$this->database->prepare('DELETE FROM selections WHERE job=? AND name=?');$query->execute([$job,$name]);}
}
foreach([[false,null,'1',false,null],[true,'0','1',true,'0'],[false,null,'0',true,'0'],[true,'yes','1',true,'1']] as [$present,$baseline,$current,$retained,$expected]){
    $backup=new PersistedBackupSelection();$backup->setConfig('core','1','modules_job');$backup->setConfig('unrelated','retained','modules_job');$backup->setConfig('slsmassnotifyserver',$current,'modules_job');
    $module=new FreePBX\modules\Slsmassnotifyserver((object)['Backup'=>$backup]);
    $module->restoreFreePbxBackupEnrollment([['job'=>'job','present'=>$present,'value'=>$baseline]]);
    $selection=$backup->getAll('modules_job');
    checkEnrollment(array_key_exists('slsmassnotifyserver',$selection)===$retained,'Rollback must restore only the exact owned native enrollment');
    if($retained){checkEnrollment($selection['slsmassnotifyserver']===$expected,'Persisted scalar or independent administrator edit was not preserved');}
    checkEnrollment($selection['core']==='1'&&$selection['unrelated']==='retained','Rollback changed unrelated job selection');
}
echo "Persisted backup enrollment restoration preserves native scalars and independent selections.\n";
