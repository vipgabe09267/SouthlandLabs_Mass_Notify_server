<?php
/** Apache binding/name precedence must select the route before credentials. */
namespace FreePBX\modules {
    require __DIR__.'/fixtures/local_web_curl.php';
    $GLOBALS['localWebCurlObserver']=static function($url,$options){$GLOBALS['precedenceRequests'][]=[$url,$options];return '{}';};
}
namespace {
    require_once dirname(__DIR__).'/slsmassnotifyserver/LocalWebProbe.php';
    use FreePBX\modules\SlsLocalWebProbe;
    $failures = [];
    function precedenceRequests($vhosts, $config) {
        $GLOBALS['precedenceRequests'] = [];
        try {
            iterator_to_array(SlsLocalWebProbe::responses('pbx.example.test', '/api/sls-mass-notify/?resource=status',
                ['Authorization: Bearer inert-precedence-fixture', 'Accept: application/json'], 1, $vhosts, $config));
        } catch (RuntimeException $error) {}
        return $GLOBALS['precedenceRequests'];
    }
    function hosts($requests) { return array_map(static fn($request) => trim(explode(':', $request[1][CURLOPT_RESOLVE][0], 3)[2], '[]'), $requests); }
    $native = "127.0.0.1:8443 unrelated.example.test (/audit/explicit.conf:1)\n*:8443 pbx.example.test (/audit/wildcard.conf:1)\n";
    $config = "Listen 8443\n<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n"
        ."<VirtualHost 127.0.0.1:8443>\nServerName unrelated.example.test\nDocumentRoot /srv/unrelated\nSSLEngine on\n</VirtualHost>\n";
    $requests = precedenceRequests($native, $config);
    if (in_array('127.0.0.1', hosts($requests), true)) { $failures[] = 'An explicit unrelated IPv4 vhost must shadow wildcard PBX authority before Authorization is sent.'; }
    if (!in_array('::1', hosts($requests), true)) { $failures[] = 'The independently selected wildcard PBX on IPv6 must remain available.'; }

    $shadowed = "*:8443 is a NameVirtualHost\n default server decoy.example.test (/audit/first.conf:1)\n"
        ." port 8443 namevhost decoy.example.test (/audit/first.conf:1)\n alias pbx.example.test\n"
        ." port 8443 namevhost pbx.example.test (/audit/second.conf:1)\n";
    $wrong = "<VirtualHost *:8443>\nServerName decoy.example.test\nServerAlias pbx.example.test\nDocumentRoot /srv/unrelated\nSSLEngine on\n</VirtualHost>\n";
    $pbx = "<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n";
    if (precedenceRequests($shadowed, "Listen 8443\n".$wrong.$pbx) !== []) {
        $failures[] = 'The first matching wrong-root ServerAlias must shadow a later canonical vhost before Authorization is sent.';
    }
    $first = "*:8443 is a NameVirtualHost\n default server pbx.example.test (/audit/first.conf:1)\n"
        ." port 8443 namevhost pbx.example.test (/audit/first.conf:1)\n"
        ." port 8443 namevhost decoy.example.test (/audit/second.conf:1)\n alias pbx.example.test\n";
    if (count(precedenceRequests($first, "Listen 8443\n".$pbx.$wrong)) !== 2) {
        $failures[] = 'A first matching canonical PBX must remain usable despite a later shadowed alias.';
    }
    $explicitPbx = "127.0.0.1:8443 pbx.example.test (/audit/explicit.conf:1)\n*:8443 unrelated.example.test (/audit/wildcard.conf:1)\n";
    $exact = str_replace('*:8443', '127.0.0.1:8443', $pbx);
    $other = str_replace('decoy.example.test', 'unrelated.example.test', str_replace("ServerAlias pbx.example.test\n", '', $wrong));
    $requests = precedenceRequests($explicitPbx, "Listen 8443\n".$other.$exact);
    if (hosts($requests) !== ['127.0.0.1']) { $failures[] = 'An exact canonical IPv4 PBX binding must remain available while unrelated IPv6 wildcard authority is excluded.'; }
    if ($failures) { foreach ($failures as $failure) { fwrite(STDERR, $failure."\n"); } exit(1); }
    echo "Local credentials follow Apache exact-address priority and first matching hostname authority.\n";
}
