<?php
declare(strict_types=1);

// Characterize SLL's native lifecycle boundary: FreePBX calls BMO and legacy
// scripts separately. Reintroducing a delegation from install.php/uninstall.php
// must fail by repeating the integration side effect, even when each phase is
// otherwise idempotent. No actual PBX state is loaded or modified.
// The fallback dispatcher methods below are verbatim from FreePBX Framework
// 7dde21b81e4dd6416018ebb7a102df231503ddbd (GPL-3.0):
// https://github.com/FreePBX/framework/blob/7dde21b81e4dd6416018ebb7a102df231503ddbd/amp_conf/htdocs/admin/libraries/modulefunctions.class.php#L2566
// --native-framework PATH repeats the same check using an installed dispatcher.

interface BMO {}
require dirname(__DIR__).'/slsmassnotifyserver/Slsmassnotifyserver.class.php';
function lifecycle_check(bool $ok, string $message): void {
    if (!$ok) { throw new RuntimeException($message); }
}
function dbug($value): void {}

final class FreePBX {
    public static $instance;
    public $Slsmassnotifyserver;
    public static function create() { return self::$instance; }
    public static function Modules() { return new class {
        public function cleanModuleName($name) {
            lifecycle_check($name === 'slsmassnotifyserver', 'Unexpected native module name.');
            return 'Slsmassnotifyserver';
        }
    }; }
    public function injectClass($name, $file): void {
        lifecycle_check($name === 'Slsmassnotifyserver' && is_file($file), 'Wrong BMO class injection.');
    }
}

final class PinnedNativeLifecycle {
	function _runscripts($modulename, $type, $modulexml = false) {
		global $amp_conf;
		$db_engine = $amp_conf["AMPDBENGINE"];

		$moduledir = $amp_conf["AMPWEBROOT"]."/admin/modules/".$modulename;
		if (!is_dir($moduledir)) {
			return false;
		}

		switch ($type) {
			case 'install':
				// install sql files
				$sqlfilename = "install.sql";
				$rc = true;

				if (is_file($moduledir.'/'.$sqlfilename)) {
					$rc = execSQL($moduledir.'/'.$sqlfilename);
				}

				//include additional files developer requested
				if ($modulexml !== false) {
					$this->_runscripts_include($modulexml, $type);
				}

				// If it's a BMO module, manually include the file.
				$mn = \FreePBX::Modules()->cleanModuleName($modulename);
				$bmofile = "$moduledir/$mn.class.php";
				if (file_exists($bmofile)) {
					FreePBX::create()->injectClass($mn, $bmofile);
					$o = FreePBX::create()->$mn->install();
					if($o === false) {
						return false;
					}
				}

				// then run .php scripts
				return ($this->_doinclude($moduledir.'/install.php', $modulename) && $rc);
			break;
			case 'uninstall':
				//include additional files developer requested
				if ($modulexml !== false) {
					$this->_runscripts_include($modulexml, $type);
				}

				// run uninstall .php scripts first
				$rc = $this->_doinclude($moduledir.'/uninstall.php', $modulename);

				$sqlfilename = "uninstall.sql";

				// If it's a BMO module, run uninstall.
				$mn = \FreePBX::Modules()->cleanModuleName($modulename);
				$bmofile = "$moduledir/$mn.class.php";
				if (file_exists($bmofile)) {
					try {
						$o = FreePBX::create()->$mn->uninstall();
						if($o === false) {
							return false;
						}
					} catch(Exception $e) {
						dbug("Error Returned was: ".$e->getMessage());
						return false;
					}
				}

				// then uninstall sql files
				if (is_file($moduledir.'/'.$sqlfilename)) {
					return ($rc && execSQL($moduledir.'/'.$sqlfilename));
				} else {
					return $rc;
				}

			break;
			case 'enable':
				// If it's a BMO module, manually include the file.
				$mn = \FreePBX::Modules()->cleanModuleName($modulename);
				$bmofile = "$moduledir/$mn.class.php";
				if (file_exists($bmofile)) {
					if(\FreePBX::Modules()->moduleHasMethod($modulename, 'enable')) {
						try {
							$o = FreePBX::create()->$mn->enable();
							if($o === false) {
								return false;
							}
						} catch(Exception $e) {
							dbug("Error Returned was: ".$e->getMessage());
							return false;
						}
					}
				}
			break;
			case 'disable':
				// If it's a BMO module, run uninstall.
				$mn = \FreePBX::Modules()->cleanModuleName($modulename);
				$bmofile = "$moduledir/$mn.class.php";
				if (file_exists($bmofile)) {
					if(\FreePBX::Modules()->moduleHasMethod($modulename, 'disable')) {
						try {
							$o = FreePBX::create()->$mn->disable();
							if($o === false) {
								return false;
							}
						} catch(Exception $e) {
							dbug("Error Returned was: ".$e->getMessage());
							return false;
						}
					}
				}
			break;
			default:
				return false;
		}

		return true;
	}

	function _doinclude($filename, $modulename) {
		// we provide the following variables to the included file (as well as $filename and $modulename)
		global $db, $amp_conf, $asterisk_conf;

		if (file_exists($filename) && is_file($filename)) {
			return include_once($filename);
		} else {
			return true;
		}
	}
}

$native = null;
if ($argc !== 1) {
    lifecycle_check($argc === 3 && $argv[1] === '--native-framework', 'Usage: test_native_module_lifecycle.php [--native-framework PATH]');
    require $argv[2];
    $native = (new ReflectionClass('module_functions'))->newInstanceWithoutConstructor();
}
if ($native === null) { $native = new PinnedNativeLifecycle(); }

// Keep the production entry methods real. Integration phases are the external
// boundary: a live phase changes AMI, dialplan, recordings, jobs and backups.
// Record that boundary instead of changing a running PBX during a build.
$reflection = new ReflectionClass(FreePBX\modules\Slsmassnotifyserver::class);
$source = file($reflection->getFileName());
$entryMethods = '';
foreach (['install', 'uninstall'] as $name) {
    $method = $reflection->getMethod($name);
    $entryMethods .= implode('', array_slice($source, $method->getStartLine()-1, $method->getEndLine()-$method->getStartLine()+1));
}
eval('final class LifecycleModule {
    public $events = []; public $fail = false;
    public function installUnprivilegedPhase() { $this->events[] = "install"; return !$this->fail; }
    public function uninstallUnprivilegedPhase() { $this->events[] = "uninstall"; return !$this->fail; }
    '.$entryMethods.'
}');
$pbx = new FreePBX(); $module = new LifecycleModule();
$pbx->Slsmassnotifyserver = $module; FreePBX::$instance = $pbx;
$root = sys_get_temp_dir().'/sls-native-lifecycle-'.bin2hex(random_bytes(8));
$moduleDirectory = $root.'/admin/modules/slsmassnotifyserver';
mkdir($moduleDirectory, 0700, true);
register_shutdown_function(static function() use ($root, $moduleDirectory): void {
    foreach (glob($moduleDirectory.'/*') as $file) { unlink($file); }
    rmdir($moduleDirectory); rmdir(dirname($moduleDirectory)); rmdir($root.'/admin'); rmdir($root);
});
file_put_contents($moduleDirectory.'/Slsmassnotifyserver.class.php', '<?php // Already injected by inert boundary fixture.');
foreach (['install.php', 'uninstall.php'] as $file) {
    copy(dirname(__DIR__).'/slsmassnotifyserver/'.$file, $moduleDirectory.'/'.$file);
}
$GLOBALS['amp_conf'] = ['AMPWEBROOT'=>$root, 'AMPDBENGINE'=>'mysql'];
define('FREEPBX_IS_AUTH', true);

$failures = [];
foreach (['install', 'uninstall'] as $action) {
    try {
    $module->events = []; $module->fail = false;
    lifecycle_check($native->_runscripts('slsmassnotifyserver', $action) !== false, 'Native '.$action.' unexpectedly failed.');
    lifecycle_check($module->events === [$action], 'Native '.$action.' repeated the SLL integration phase: '.json_encode($module->events));
    lifecycle_check($native->_runscripts('slsmassnotifyserver', $action) !== false, 'Repeated native '.$action.' failed.');
    lifecycle_check($module->events === [$action, $action], 'Repeated native '.$action.' did not run exactly once per request.');
    $module->events = []; $module->fail = true;
    lifecycle_check($native->_runscripts('slsmassnotifyserver', $action) === false, 'Native '.$action.' swallowed a phase failure.');
    lifecycle_check($module->events === [$action], 'Failed native '.$action.' repeated its integration phase.');
    } catch (RuntimeException $error) {
        $failures[] = $error->getMessage();
    }
}
lifecycle_check($failures === [], implode("\n", $failures));
foreach (['install.php', 'uninstall.php'] as $file) {
    $command = [PHP_BINARY, '-n', $moduleDirectory.'/'.$file];
    $process = proc_open($command, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
    lifecycle_check(is_resource($process), 'Could not execute unauthenticated lifecycle hook.');
    fclose($pipes[0]); $output = stream_get_contents($pipes[1]); $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); $status = proc_close($process);
    lifecycle_check($status === 0 && $output === 'No direct script access allowed' && $error === '', 'Unauthenticated hook reached PBX integration.');
}
echo "Native FreePBX lifecycle runs each SLL phase once; failures and direct-access guards are preserved.\n";
