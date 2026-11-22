<?php
namespace FreePBX\modules {
    $authorityUnavailableRequests = 0;
    $authorityUnavailableCommands = [];
    function function_exists($name) { return $name === 'curl_init' || \function_exists($name); }
    function defined($name) { return $name === 'CURLOPT_CONNECT_TO' || \defined($name); }
    function exec($command, &$output, &$status) {
        $GLOBALS['authorityUnavailableCommands'][] = $command;
        $output = []; $status = 1;
    }
    function curl_init($url) {
        $GLOBALS['authorityUnavailableRequests']++;
        throw new \RuntimeException('No HTTPS request may occur without native route authority');
    }
    function file_get_contents($url, $includePath, $context, $offset, $length) {
        $GLOBALS['authorityUnavailableRequests']++;
        throw new \RuntimeException('No stream request may occur without native route authority');
    }
}
namespace {
    require_once dirname(__DIR__).'/slsmassnotifyserver/LocalWebProbe.php';
    require_once dirname(__DIR__).'/slsmassnotifyserver/AdvertisedAddress.php';
    $settings = [
        'public_pbx_host' => 'pbx.example.test',
        'sipnotify' => ['base_url' => 'https://pbx.example.test/api/sipnotify', 'api_key' => 'never-send-this-api-key'],
        'control_api' => ['token' => 'never-send-this-control-token'],
    ];
    try { $result = FreePBX\modules\SlsAdvertisedAddress::checkLocalHttps($settings); }
    catch (Throwable $error) {
        fwrite(STDERR, "Unavailable native authority must return an advertised-address diagnostic, not abort its editor.\n"); exit(1);
    }
    $message = $result['message'] ?? '';
    if (($result['ok'] ?? true) !== false || !str_contains(strtolower($message), 'root-assisted')) {
        fwrite(STDERR, "The advertised-address check must explain the required root-assisted route check.\n"); exit(1);
    }
    if ($GLOBALS['authorityUnavailableRequests'] !== 0
        || str_contains($message, 'never-send-this-')
        || str_contains(implode("\n", $GLOBALS['authorityUnavailableCommands']), 'never-send-this-')) {
        fwrite(STDERR, "Unavailable authority must not start requests or expose saved credentials.\n"); exit(1);
    }
    echo "Unavailable native authority remains a safe advertised-address diagnostic.\n";
}
