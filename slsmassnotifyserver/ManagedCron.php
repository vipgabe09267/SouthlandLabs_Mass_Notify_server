<?php
namespace FreePBX\modules;

/** Fixed SLL execution ownership, without evaluating shell text or its data. */
final class SlsManagedCron
{
    private const SCRIPTS = ['sls_cron_runner.py', 'sls_mass_notify_weather_poll.sh', 'sls_mass_notify_nws_poll.sh',
        'sls_mass_notify_schedule_worker.php', 'sls_mass_notify_announcement_worker.php',
        'sls_mass_notify_update.sh', 'sls_mass_notify_maintenance.sh', 'nws_weather_alert.sh',
        'nwsalerts_ensure_menu_patch.sh', 'sign_sls_mass_notify_local_sig.sh'];
    private const CONTROLS = [';', '&&', '||', '|', '&', '(', ')'];
    private const REDIRECTS = ['>', '>>', '<', '>&', '<&', '>|', '<<', '<<<'];

    private static function review(): void
    {
        throw new \RuntimeException('An unknown or ambiguous SLL cron command requires administrator review. Existing cron entries were preserved.');
    }

    private static function mentions(string $value): bool
    {
        foreach (array_merge(self::SCRIPTS, ['/usr/local/bin/sls_mass_notify/', '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh',
            '/var/www/html/admin/modules/slsmassnotifyserver/', 'SLS_Mass_Notifications_Plugin']) as $marker) {
            if (strpos($value, $marker) !== false) { return true; }
        }
        return false;
    }

    /** Bounded POSIX shell words and punctuation; no expansion or execution. */
    private static function words(string $text): array
    {
        $words = []; $word = ''; $started = false; $literal = false; $quote = ''; $length = strlen($text);
        for ($i = 0; $i < $length; $i++) {
            $char = $text[$i];
            if ($quote === "'") {
                if ($char === "'") { $quote = ''; } else { $word .= $char; }
                continue;
            }
            if ($char === '\\' && $quote !== "'") {
                if (++$i >= $length) { throw new \RuntimeException('Incomplete shell escape'); }
                $next = $text[$i];
                if ($quote === '"' && !in_array($next, ['$', '`', '"', '\\', "\n"], true)) { $word .= '\\'; }
                $word .= $next; $started = true; $literal = true; continue;
            }
            if ($quote === '"') {
                if ($char === '"') { $quote = ''; }
                else {
                    if (($char === '`' || ($char === '$' && substr($text, $i, 2) === '$(')) && self::mentions($text)) { self::review(); }
                    $word .= $char;
                }
                continue;
            }
            if ($char === "'" || $char === '"') { $quote = $char; $started = true; $literal = true; continue; }
            if ($char === '#') { break; }
            if ($char === '`' && self::mentions($text)) { self::review(); }
            if (strpos(" \t\n", $char) !== false) {
                if ($started) { $words[] = ctype_digit($word) ? "\1" . $word : $word; $word = ''; $started = false; $literal = false; }
                continue;
            }
            if (strpos(';&|()<>', $char) !== false) {
                if ($started) { $words[] = $literal && ctype_digit($word) ? "\1" . $word : $word; $word = ''; $started = false; $literal = false; }
                $operator = $char;
                while ($i + 1 < $length && strpos(';&|()<>', $text[$i + 1]) !== false) { $operator .= $text[++$i]; }
                $words[] = "\0" . $operator; continue;
            }
            $word .= $char; $started = true;
        }
        if ($quote !== '') { throw new \RuntimeException('Incomplete shell quote'); }
        if ($started) { $words[] = ctype_digit($word) ? "\1" . $word : $word; }
        return $words;
    }

    private static function command(array $tokens, string $account): bool
    {
        $arguments = []; $redirects = [];
        for ($i = 0; $i < count($tokens); $i++) {
            $token = $tokens[$i]; $descriptor = null;
            $operator = $token !== '' && $token[0] === "\0" ? substr($token, 1) : null;
            $next = $tokens[$i + 1] ?? '';
            $nextOperator = $next !== '' && $next[0] === "\0" ? substr($next, 1) : null;
            if (ctype_digit($token) && in_array($nextOperator, self::REDIRECTS, true)) {
                $descriptor = $token; $operator = $nextOperator; $i++;
            }
            if (in_array($operator, self::REDIRECTS, true)) {
                if (!isset($tokens[$i + 1]) || ($tokens[$i + 1] !== '' && $tokens[$i + 1][0] === "\0")) { self::review(); }
                $target = $tokens[++$i];
                $redirects[] = [$descriptor, $operator, $target !== '' && $target[0] === "\1" ? substr($target, 1) : $target];
            } else { $arguments[] = $token !== '' && $token[0] === "\1" ? substr($token, 1) : $token; }
        }
        $mentioned = self::mentions(implode(' ', $arguments));
        while ($arguments && preg_match('/^[A-Za-z_][A-Za-z0-9_]*=.*/sD', $arguments[0])) { array_shift($arguments); }
        if (!$arguments) { return false; }
        for ($depth = 0; $depth < 4; $depth++) {
            if (!$arguments) { return false; }
            $executable = $arguments[0];
            if (in_array($executable, ['exec', '/usr/bin/env', '/bin/env', 'env'], true)) {
                array_shift($arguments);
                if ($executable !== 'exec') {
                    while ($arguments) {
                        if (in_array($arguments[0], ['-i', '--ignore-environment'], true)) { array_shift($arguments); }
                        elseif (in_array($arguments[0], ['-u', '--unset'], true) && count($arguments) > 1) { array_splice($arguments, 0, 2); }
                        elseif (preg_match('/^[A-Za-z_][A-Za-z0-9_]*=.*/sD', $arguments[0])) { array_shift($arguments); }
                        elseif ($arguments[0] === '--') { array_shift($arguments); break; }
                        elseif (strpos($arguments[0], '-') === 0) { if ($mentioned) { self::review(); } return false; }
                        else { break; }
                    }
                }
                continue;
            }
            if (in_array($executable, ['/usr/bin/timeout', '/bin/timeout', 'timeout'], true)) {
                array_shift($arguments);
                while ($arguments && strpos($arguments[0], '--') === 0) {
                    if (!preg_match('/^--(?:signal=[A-Za-z0-9]+|kill-after=[0-9]+(?:\.[0-9]+)?[smhd]?)$/D', $arguments[0])) {
                        if ($mentioned) { self::review(); } return false;
                    }
                    array_shift($arguments);
                }
                if (!$arguments || !preg_match('/^[0-9]+(?:\.[0-9]+)?[smhd]?$/D', $arguments[0])) { if ($mentioned) { self::review(); } return false; }
                array_shift($arguments); continue;
            }
            break;
        }
        if ($depth === 4) { if ($mentioned) { self::review(); } return false; }
        if (!$arguments) { return false; }
        $executable = array_shift($arguments);
        if ($mentioned && (in_array($executable, ['.', 'source', 'eval', 'command', 'builtin'], true) || strpos($executable, '$') !== false || strpos($executable, '`') !== false)) { self::review(); }
        $interpreter = basename($executable);
        if (in_array($interpreter, ['sh', 'bash', 'php'], true) || preg_match('/^python3(?:\.[0-9]{1,2})?$/D', $interpreter)) {
            $allowed = in_array($executable, ['sh', 'bash', 'php', '/bin/sh', '/usr/bin/sh', '/bin/bash', '/usr/bin/bash', '/usr/bin/php'], true)
                || preg_match('~^(?:/usr/bin/)?python3(?:\.[0-9]{1,2})?$~D', $executable);
            if (!$allowed) { if ($mentioned) { self::review(); } return false; }
            $flags = strpos($interpreter, 'python') === 0 ? ['-I', '-B', '-u'] : ($interpreter === 'php' ? ['-f'] : ['-e', '-u']);
            while ($arguments && in_array($arguments[0], $flags, true)) { array_shift($arguments); }
            if ($arguments && $arguments[0] === '--') { array_shift($arguments); }
            if (!$arguments) { return false; }
            if (strpos($arguments[0], '-') === 0) { if ($mentioned) { self::review(); } return false; }
            $executable = array_shift($arguments);
        } elseif (in_array($interpreter, ['nice', 'flock', 'runuser', 'su', 'sudo', 'env', 'timeout', 'nohup', 'setsid', 'xargs', 'time', 'stdbuf', 'ionice', 'chrt', 'taskset', 'prlimit', 'setpriv', 'systemd-run', 'doas', 'for', 'if', 'while', 'until', 'case'], true)) {
            if ($mentioned) { self::review(); } return false;
        }
        if ($mentioned && (strpos($executable, '$') !== false || strpos($executable, '`') !== false)) { self::review(); }
        $name = basename($executable);
        $ownedPath = strpos($executable, '/usr/local/bin/sls_mass_notify/') === 0
            || strpos($executable, '/var/www/html/admin/modules/slsmassnotifyserver/bin/') === 0
            || strpos($executable, '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/') === 0;
        if ($account === 'root' && in_array($name, ['nws_weather_alert.sh', 'nwsalerts_ensure_menu_patch.sh'], true) && !$ownedPath) { return false; }
        if (!$ownedPath && !in_array($name, self::SCRIPTS, true)) { return false; }
        $directories = ['/usr/local/bin/sls_mass_notify', '/var/www/html/admin/modules/slsmassnotifyserver/bin', '/var/lib/asterisk/bin', '/usr/local/bin'];
        if (!in_array($name, self::SCRIPTS, true) || (!in_array(dirname($executable), $directories, true)
            && $executable !== '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh')) { self::review(); }
        if ($name === 'sls_cron_runner.py') {
            $jobs = $account === 'root' ? ['maintenance', 'update'] : ['weather', 'scheduling', 'announcement_reconcile'];
            $valid = count($arguments) === 1 && in_array($arguments[0], $jobs, true);
        } elseif ($name === 'sls_mass_notify_announcement_worker.php') { $valid = $arguments === [] || $arguments === ['--reconcile']; }
        elseif ($name === 'sign_sls_mass_notify_local_sig.sh') { $valid = $arguments === [] || (count($arguments) === 1 && in_array($arguments[0], ['slsmassnotifyserver', 'dashboard', 'framework'], true)); }
        else { $valid = $arguments === []; }
        if (!$valid) { self::review(); }
        foreach ($redirects as [$fd, $operation, $target]) {
            if (!(in_array($fd, [null, '1'], true) && in_array($operation, ['>', '>>'], true) && $target === '/dev/null')
                && !($fd === '2' && $operation === '>&' && $target === '1')) { self::review(); }
        }
        return true;
    }

    public static function owns(string $line, string $account = 'asterisk'): bool
    {
        if (strlen($line) > 65536 || preg_match('/[\x00-\x08\x0b-\x1f\x7f]/', $line) || !in_array($account, ['asterisk', 'root'], true)) { self::review(); }
        $text = trim($line);
        if ($text === '' || $text[0] === '#' || preg_match('/^[A-Za-z_][A-Za-z0-9_]*\s*=/', $text)) { return false; }
        $parts = preg_split('/\s+/', $text, $text[0] === '@' ? 2 : 6);
        if (count($parts) !== ($text[0] === '@' ? 2 : 6)) { if (self::mentions($text)) { self::review(); } return false; }
        $command = end($parts);
        try { $tokens = self::words($command); }
        catch (\RuntimeException $error) { if (self::mentions($command)) { self::review(); } return false; }
        $segments = []; $current = []; $compound = false;
        foreach ($tokens as $token) {
            if ($token !== '' && $token[0] === "\0" && in_array(substr($token, 1), self::CONTROLS, true)) {
                $compound = true; if ($current) { $segments[] = $current; $current = []; }
            } else { $current[] = $token; }
        }
        if ($current) { $segments[] = $current; }
        $owned = false;
        foreach ($segments as $segment) { if (self::command($segment, $account)) { $owned = true; } }
        if ($owned && $compound) { self::review(); }
        return $owned;
    }
}
