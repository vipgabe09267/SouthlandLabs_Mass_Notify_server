<?php
/** Exercise the two legacy Apache dispatcher aliases against a private filesystem fixture. */
namespace FreePBX\modules {
    function lstat($path) {
        $info = @\lstat($GLOBALS['aliasFixture'] . $path);
        if (is_array($info) && isset($GLOBALS['aliasMetadata'][$path])) {
            $info = array_replace($info, $GLOBALS['aliasMetadata'][$path]);
        }
        return $info;
    }
    function fopen($path, $mode) { return \fopen($GLOBALS['aliasFixture'] . $path, $mode); }
    function posix_getpwnam($name) {
        return ['uid'=>\posix_geteuid() ?: 19999, 'gid'=>\posix_getegid() ?: 19999];
    }
}
namespace {
    use FreePBX\modules\SlsLocalWebProbe;
    require dirname(__DIR__) . '/slsmassnotifyserver/LocalWebProbe.php';
    $root = sys_get_temp_dir() . '/sll-dispatch-' . bin2hex(random_bytes(8));
    $GLOBALS['aliasFixture'] = $root;
    $GLOBALS['aliasMetadata'] = [];
    function targets($name, $route, $alias = null) {
        $alias ??= 'Alias "/api/' . $name . '" "/var/www/html/api/' . $name . '.php"';
        $vhosts = "127.0.0.1:8811 pbx.example.test (/etc/apache2/sites-enabled/pbx.conf:1)\n";
        $config = "Listen 127.0.0.1:8811\n<VirtualHost 127.0.0.1:8811>\nServerName pbx.example.test\n"
            . "DocumentRoot /var/www/html\n" . $alias . "\n</VirtualHost>";
        return (bool) SlsLocalWebProbe::targets('pbx.example.test', $vhosts, $config, $route);
    }
    $failed = [];
    function check($actual, $expected, $case) {
        if ($actual !== $expected) { $GLOBALS['failed'][] = $case; }
    }
    function removeFixture($path) {
        if (!is_link($path) && is_dir($path)) {
            foreach (new \FilesystemIterator($path) as $entry) { removeFixture($entry->getPathname()); }
            rmdir($path);
        } else { unlink($path); }
    }
    umask(0022);
    mkdir($root, 0755);
    try {
        foreach (['sipnotify', 'sls-mass-notify'] as $name) {
            $route = '/api/' . $name;
            $script = '/var/www/html' . $route . '.php';
            $public = '/var/www/html' . $route . '/index.php';
            $module = '/var/www/html/admin/modules/slsmassnotifyserver' . $route . '/index.php';
            foreach ([$public, $module] as $file) {
                mkdir(dirname($root . $file), 0755, true);
                copy(dirname(__DIR__) . '/slsmassnotifyserver' . $route . '/index.php', $root . $file);
                chmod($root . $file, 0644);
            }
            $comment = $name === 'sls-mass-notify' ? "// Southland Servers Mass Notifications Server by the Southland Servers Group\n" : '';
            $code = "<?php\n" . $comment . "require __DIR__ . '/" . $name . "/index.php';\n";
            file_put_contents($root . $script, $code);
            chmod($root . $script, 0644);
            // Independent 0.2.0 source supplies the expected bytes at both destinations.
            $paths = $name === 'sipnotify' ? ['/desktop', '/desktop/stream?stream_seconds=1'] : ['/?resource=status', '/sms-callback.php'];
            foreach ($paths as $path) { check(targets($name, $route . $path), true, $name . $path); }
            if ($name === 'sls-mass-notify') {
                check(targets($name, '/sls_mass_notify/media_probe_123.png'), true, 'legacy media internal target');
                check(targets($name, '/sls_mass_notify/media_probe_123.png', 'Alias "/api/sls-mass-notify/media.php" "/srv/foreign.php"'), false, 'redirected media alias');
                check(targets($name, $route . '/', 'Alias "/api/sls-mass-notify/index.php" "/srv/foreign.php"'), false, 'redirected DirectoryIndex alias');
            }
            $request = $route . $paths[0];
            check(targets($name, $route . '/unreviewed.php'), false, 'unknown probe ' . $name);
            foreach ([$script . '/', '/var/www/html/api/other.php', $public] as $aliasTo) {
                check(targets($name, $request, 'Alias "' . $route . '" "' . $aliasTo . '"'), false, 'wrong destination ' . $aliasTo);
            }
            check(targets($name, $request, 'Alias "' . $route . '/" "' . $script . '"'), false, 'changed source prefix');
            file_put_contents($root . $script, $code . "echo 'extra';\n");
            check(targets($name, $request), false, 'modified dispatcher');
            file_put_contents($root . $script, $code);
            foreach ([$script, $public, $module] as $file) {
                rename($root . $file, $root . $file . '.saved');
                check(targets($name, $request), false, 'missing ' . $file);
                symlink($root . $file . '.saved', $root . $file);
                check(targets($name, $request), false, 'symlink ' . $file);
                unlink($root . $file);
                link($root . $file . '.saved', $root . $file);
                check(targets($name, $request), false, 'hardlink ' . $file);
                unlink($root . $file);
                rename($root . $file . '.saved', $root . $file);
                chmod($root . $file, 0666);
                check(targets($name, $request), false, 'world writable ' . $file);
                chmod($root . $file, 0000);
                check(targets($name, $request), false, 'unreadable ' . $file);
                chmod($root . $file, 0644);
                $GLOBALS['aliasMetadata'][$file] = ['uid'=>61234];
                check(targets($name, $request), false, 'unrelated owner ' . $file);
                unset($GLOBALS['aliasMetadata'][$file]);
            }
            chmod(dirname($root . $public), 0777);
            check(targets($name, $request), false, 'writable ancestor');
            chmod(dirname($root . $public), 0755);
            file_put_contents($root . $public, "<?php\n// foreign\n");
            check(targets($name, $request), false, 'unexpected public index');
            copy($root . $public, $root . $module);
            check(targets($name, $request), false, 'unreviewed matching indexes');
        }
    } finally { removeFixture($root); }
    if ($failed) { fwrite(STDERR, implode("\n", $failed) . "\n"); exit(1); }
    echo "Legacy API dispatch requires exact wrappers, signed index bytes, safe ownership, modes and canonical files.\n";
}
