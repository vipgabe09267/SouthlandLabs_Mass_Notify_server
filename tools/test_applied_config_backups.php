<?php
/** Exercise retained pre-Apply snapshots with the actual facade and crypto. */
interface BMO {}
class FreePBX
{
    public static function Config()
    {
        return new class { public function get($key) { return ''; } };
    }
}

// This fixture uses the real fixed runtime paths only after the normal runner
// has hidden PBX state behind fresh mount, network and PID namespaces.
foreach (['MOUNT' => 'mnt', 'NET' => 'net', 'PID' => 'pid'] as $kind => $path) {
    $parent = getenv('SLS_TEST_PARENT_' . $kind . '_NS');
    if (getenv('SLS_TEST_NAMESPACE') !== 'entered' || !$parent
        || $parent === readlink('/proc/self/ns/' . $path)) {
        throw new RuntimeException('Run this fixture through tools/run_isolated_tests.sh.');
    }
}
require dirname(__DIR__) . '/slsmassnotifyserver/Slsmassnotifyserver.class.php';
use FreePBX\modules\Slsmassnotifyserver as Module;
use FreePBX\modules\SlsConfigCrypto as Crypto;

$checks = 0;
function check($value, $message)
{
    $GLOBALS['checks']++;
    if (!$value) { throw new RuntimeException($message); }
}
function invokePrivate($object, $name, array $arguments = [])
{
    $method = new ReflectionMethod($object, $name);
    $method->setAccessible(true);
    return $method->invokeArgs($object, $arguments);
}
function snapshots()
{
    $files = glob(Module::PLUGIN_DATA_DIR . '/config-backups/mass-notifications-*.config') ?: [];
    sort($files);
    return $files;
}
function installFixtureConfig($module, array $settings)
{
    $contents = Crypto::encode($settings);
    file_put_contents(Module::SETTINGS_JSON, $contents);
    invokePrivate($module, 'setPrivateOwnership', [Module::SETTINGS_JSON]);
    return $contents;
}

$reflection = new ReflectionClass(Module::class);
$module = $reflection->newInstanceWithoutConstructor();
invokePrivate($module, 'ensureOwnedDirectory', [Module::PLUGIN_DATA_DIR, 0750]);
$settings = [
    'enabled' => '0', 'setup' => ['completed' => '1'],
    'ami' => ['username' => 'slsmassnotify', 'password' => 'fixture-secret', 'host' => '127.0.0.1', 'port' => 5038],
    'control_api' => ['enabled' => '0', 'api_key' => 'abcdefghijklmnopqrstuvwxyz123456'],
    'sipnotify' => [], 'desktop_clients' => [], 'announcement_groups' => [],
    'scheduled_announcements' => [], 'discord_webhooks' => [], 'generic_webhooks' => [],
    'alert_email_body' => '',
];
// These are accepted settings, including a large text field saved by the GUI.
// The writer bounds pretty JSON; encryption uses compact JSON plus Base64.
$emptyPretty = json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
$cases = ['small' => 32, 'large' => 1700000,
    'maximum-admitted' => Module::NATIVE_BACKUP_MAX_CONFIG_BYTES - strlen($emptyPretty)];
foreach ($cases as $name => $length) {
    $settings['alert_email_body'] = str_repeat('x', $length);
    $plain = json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    check(strlen($plain) <= Module::NATIVE_BACKUP_MAX_CONFIG_BYTES, $name . ': fixture exceeds the admitted plaintext bound.');
    check(invokePrivate($module, 'validateNativeBackupConfig', [$plain]) === $settings,
        $name . ': fixture is not accepted by the real configuration validator.');
    $cipher = installFixtureConfig($module, $settings);
    check(strlen($cipher) <= Crypto::MAX_FILE_BYTES, $name . ': ciphertext exceeds its own bound.');
    if ($name !== 'small') {
        check(strlen($cipher) > Module::NATIVE_BACKUP_MAX_CONFIG_BYTES,
            $name . ': fixture did not cross the former incorrect ciphertext bound.');
    }
    $before = snapshots();
    invokePrivate($module, 'backupAppliedSettings');
    $after = snapshots();
    check(count($after) === count($before) + 1, $name . ': accepted configuration did not receive its retained snapshot.');
    $backup = array_values(array_diff($after, $before))[0];
    $restored = Crypto::readFile($backup);
    check($restored === $settings, $name . ': encrypted snapshot changed settings.');
    check(json_encode($restored, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
        === json_encode($settings, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        $name . ': decrypted serialized settings changed.');
    check(file_get_contents(Module::SETTINGS_JSON) === $cipher, $name . ': snapshot changed the active configuration.');
    $metadata = lstat($backup); $account = posix_getpwnam('asterisk');
    check($metadata['uid'] === $account['uid'] && $metadata['gid'] === $account['gid']
        && ($metadata['mode'] & 0777) === 0640 && $metadata['nlink'] === 1,
        $name . ': snapshot did not retain private runtime ownership and permissions.');
}

// A truly oversized source still fails before generating any new snapshot.
$before = snapshots();
$oversized = str_repeat('x', Crypto::MAX_FILE_BYTES + 1);
file_put_contents(Module::SETTINGS_JSON, $oversized);
$rejected = false;
try { invokePrivate($module, 'backupAppliedSettings'); }
catch (RuntimeException $error) { $rejected = true; }
check($rejected, 'A truly oversized active configuration was accepted.');
check(snapshots() === $before && file_get_contents(Module::SETTINGS_JSON) === $oversized,
    'Oversized rejection changed the source or retained snapshots.');

// Destination safety remains enforced when the ciphertext size cap is raised.
$active = installFixtureConfig($module, $settings);
$backupDirectory = Module::PLUGIN_DATA_DIR . '/config-backups';
$savedDirectory = $backupDirectory . '.fixture-saved';
$outside = sys_get_temp_dir() . '/sls-backup-outside-' . bin2hex(random_bytes(8));
mkdir($outside, 0700); file_put_contents($outside . '/sentinel', 'preserved');
rename($backupDirectory, $savedDirectory); symlink($outside, $backupDirectory);
try {
    invokePrivate($module, 'backupAppliedSettings');
    check(is_link($backupDirectory) && scandir($outside) === ['.', '..', 'sentinel']
        && file_get_contents($outside . '/sentinel') === 'preserved',
        'An unsafe snapshot destination was followed or modified.');
    check(file_get_contents(Module::SETTINGS_JSON) === $active,
        'An unsafe snapshot destination changed the active configuration.');
} finally {
    unlink($backupDirectory); rename($savedDirectory, $backupDirectory);
    unlink($outside . '/sentinel'); rmdir($outside);
}
check(snapshots() === $before, 'Unsafe destination handling changed retained snapshots.');
echo 'Applied configuration snapshot checks passed (' . $checks . " checks).\n";
