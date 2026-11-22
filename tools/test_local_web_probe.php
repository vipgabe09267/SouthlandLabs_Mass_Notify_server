<?php
/** Fixture-only discovery and request tests: no sockets, Apache, or PBX access. */
namespace FreePBX\modules {
	function exec($command, &$output, &$status) {
		$GLOBALS['discovery_commands'][] = $command;
		$output = explode("\n",str_contains($command,'DUMP_CONFIG')?($GLOBALS['config_fixture']??''):($GLOBALS['vhost_fixture']??''));
		$status = 0;
	}
	require __DIR__.'/fixtures/local_web_curl.php';
	$GLOBALS['localWebCurlObserver']=static function($url,$options){$GLOBALS['probe_requests'][]=[$url,$options];return 'fixture response';};
}
namespace {
	require_once dirname(__DIR__) . '/slsmassnotifyserver/LocalWebProbe.php';
	require_once dirname(__DIR__) . '/slsmassnotifyserver/api/sls-mass-notify/media-policy.php';
	use FreePBX\modules\SlsLocalWebProbe;
	function check($condition, $message) {
		if (!$condition) { throw new \RuntimeException($message); }
	}
	$GLOBALS['discovery_commands']=[];
	$initial="*:8443 pbx.example.test (/etc/apache2/sites-enabled/pbx.conf:1)\n[::1]:9443 ipv6.example.test (/etc/apache2/sites-enabled/ipv6.conf:1)\n";
	$initialConfig="Listen 8443\nListen [::1]:9443\n<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n<VirtualHost [::1]:9443>\nServerName ipv6.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n";
	$GLOBALS['vhost_fixture']=$initial;$GLOBALS['config_fixture']=$initialConfig;
	$targets=SlsLocalWebProbe::targets('pbx.example.test');
	check(count($GLOBALS['discovery_commands'])===2,'Both bounded native inventories are required');
	foreach($GLOBALS['discovery_commands'] as $command){check(str_starts_with($command,'/usr/bin/timeout 5 /usr/sbin/apache2ctl -t -D '),'Native route discovery lost its deadline');}
	check($targets[0]['url']==='https://pbx.example.test:8443','Canonical hostname listener was not selected');
	check($targets[0]['resolve']==='pbx.example.test:8443:127.0.0.1','Custom HTTPS host was not pinned to loopback');
	check($targets[0]['host_header']==='pbx.example.test:8443','Custom Host port was lost');
	foreach($targets as $target){check(in_array(parse_url($target['connect_url'],PHP_URL_HOST),['127.0.0.1','[::1]'],true),'Non-loopback route accepted');check(parse_url($target['url'],PHP_URL_PORT)===8443,'Unrelated vhost became credential authority');}
	$ipv6=SlsLocalWebProbe::targets('ipv6.example.test',$initial,$initialConfig);
	check(count($ipv6)===1&&$ipv6[0]['connect_url']==='https://[::1]:9443','An IPv6-specific binding must stay IPv6-specific');
	$aliasDump="*:8443 primary.example.test (/etc/apache2/sites-enabled/pbx.conf:1)\n";
	$aliasConfig="Listen 8443\n<VirtualHost *:8443>\nServerName primary.example.test\nServerAlias pbx.example.test *.branch.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n";
	check(count(SlsLocalWebProbe::targets('pbx.example.test',$aliasDump,$aliasConfig))>0,'Effective native alias was lost');
	check(count(SlsLocalWebProbe::targets('east.branch.example.test',$aliasDump,$aliasConfig))>0,'Effective native wildcard alias was lost');
	check(SlsLocalWebProbe::targets('orphan.example.test',$aliasDump,$aliasConfig)===[],'Unrelated hostname gained alias authority');
	$many='';$config='';
	for($port=10000;$port<10017;$port++){$many.='*:'.$port." pbx.example.test (/etc/pbx.conf:1)\n";$config.='Listen '.$port."\n<VirtualHost *:".$port.">\nServerName pbx.example.test\nDocumentRoot /var/www/html\n</VirtualHost>\n";}
	$rejected=false;try{SlsLocalWebProbe::targets('pbx.example.test',$many,$config);}catch(RuntimeException $error){$rejected=true;}
	check($rejected,'More than sixteen actual PBX listeners must require qualification rather than silent truncation');
	foreach(["pbx.example.test\r\nAuthorization: injected",'https://external.invalid','external.invalid:8443'] as $invalidHost){$rejected=false;try{SlsLocalWebProbe::targets($invalidHost,$initial,$initialConfig);}catch(RuntimeException $error){$rejected=true;}check($rejected,'Invalid configured host must not become credential authority');}
	$GLOBALS['probe_requests']=[];
	foreach(SlsLocalWebProbe::responses('pbx.example.test','/api/sipnotify/desktop/stream?stream_seconds=1',['Authorization: Basic fixture','Accept: text/event-stream'],8,$initial,$initialConfig) as $response){check($response['body']==='fixture response','Probe did not return its inert response');break;}
	check(count($GLOBALS['probe_requests'])===1,'A successful consumer must retain lazy response iteration');
	[$url,$options]=$GLOBALS['probe_requests'][0];
	check($url==='https://pbx.example.test:8443/api/sipnotify/desktop/stream?stream_seconds=1' && $options[CURLOPT_RESOLVE]===['pbx.example.test:8443:127.0.0.1'],'Authenticated request escaped its actual local PBX listener');
	check($options[CURLOPT_HTTPHEADER][0]==='Host: pbx.example.test:8443' && $options[CURLOPT_HTTPHEADER][1]==='Authorization: Basic fixture','Host or credential header changed');
	check(parse_url($url,PHP_URL_HOST)==='pbx.example.test','Configured SNI was lost');
	check($options[CURLOPT_FOLLOWLOCATION]===false&&$options[CURLOPT_MAXREDIRS]===0,'Redirects could disclose credentials');
	check($options[CURLOPT_TIMEOUT_MS]<=8000&&is_callable($options[CURLOPT_WRITEFUNCTION])&&$options[CURLOPT_PROXY]===''&&$options[CURLOPT_NOPROXY]==='*','Response bounds changed');
	$GLOBALS['probe_requests']=[];$refused=false;
	try{iterator_to_array(SlsLocalWebProbe::responses('stale.example.test','/api/test',['Authorization: Bearer fixture'],1,$initial,$initialConfig));}catch(RuntimeException $error){$refused=true;}
	check($refused&&$GLOBALS['probe_requests']===[],'Stale hostname must not trigger credential fallback to a default site');
	$GLOBALS['vhost_fixture']=$initial;$GLOBALS['config_fixture']=$initialConfig;

	foreach ([['https://external.invalid', ['Accept: text/plain']], ['/api/test', ["Authorization: test\r\nInjected: value"]]] as $invalid) {
		$rejected = false;
		try { iterator_to_array(SlsLocalWebProbe::responses('pbx.example.test', $invalid[0], $invalid[1], 8, '')); }
		catch (\RuntimeException $exception) { $rejected = true; }
		check($rejected, 'Invalid request input was accepted');
	}
	foreach ([[ '/api/test', ['MalformedHeader'], 8 ], [ '/api/test', array_fill(0, 33, 'Accept: text/plain'), 8 ], [ '/api/test', ['Accept: text/plain'], 0 ]] as [$badPath,$badHeaders,$badTimeout]) {
		$rejected=false;try{iterator_to_array(SlsLocalWebProbe::responses('pbx.example.test',$badPath,$badHeaders,$badTimeout,''));}catch(\RuntimeException $exception){$rejected=true;}
		check($rejected,'Malformed header count, syntax or timeout was accepted');
	}
	$rejected=false;try{SlsLocalWebProbe::targets('pbx.example.test',[]);}catch(\InvalidArgumentException $exception){$rejected=true;}
	check($rejected,'Non-text Apache inventory was accepted');
	// Execute the installer's actual enabled-Control-API PHP with private files
	// and an inert HTTP helper, so wrong credential variables cannot pass lint.
	$fixture = sys_get_temp_dir() . '/sls-web-probe-' . bin2hex(random_bytes(8));
	check(mkdir($fixture, 0700), 'Cannot create private installer fixture');
	try {
		file_put_contents($fixture . '/config.json', json_encode(['public_pbx_host' => 'pbx.example.test', 'control_api' => ['enabled' => '1', 'api_key' => 'fixture-control-key']]));
		file_put_contents($fixture . '/helper.php', '<?php namespace FreePBX\\modules; final class SlsLocalWebProbe { public static function responses($host, $path, $headers, $timeout) { if ($host !== "pbx.example.test" || $path !== "/api/sls-mass-notify/?resource=status" || $headers !== ["Authorization: Bearer fixture-control-key", "Accept: application/json"]) { throw new \\RuntimeException("Installer authentication request was altered"); } yield ["status" => 200, "body" => "{\\"ok\\":true,\\"resource\\":\\"status\\"}"]; } }');
		$installer = file_get_contents(dirname(__DIR__) . '/tools/install_release.sh');
		$block = explode('verify_control_api_authentication() {', $installer, 2)[1];
		$block = explode("php -r '\n", $block, 2)[1];
		$block = explode("\n' >>", $block, 2)[0];
		$block = str_replace('/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config', $fixture . '/config.json', $block);
		$block = str_replace('/var/www/html/admin/modules/slsmassnotifyserver/LocalWebProbe.php', $fixture . '/helper.php', $block);
		$block = str_replace('/usr/local/bin/sls_mass_notify/sls_config_crypto.php', dirname(__DIR__) . '/slsmassnotifyserver/api/sls-mass-notify/config-crypto.php', $block);
		$pipes = [];
		$process = proc_open(['/usr/bin/php'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		check(is_resource($process), 'Cannot launch inert installer fixture');
		fwrite($pipes[0], "<?php\n" . $block); fclose($pipes[0]);
		$output = stream_get_contents($pipes[1]); fclose($pipes[1]);
		$error = stream_get_contents($pipes[2]); fclose($pipes[2]);
		check(proc_close($process) === 0 && $error === '', 'Enabled Control API installer fixture failed: ' . $error);
	} finally {
		@unlink($fixture . '/config.json'); @unlink($fixture . '/helper.php'); @rmdir($fixture);
	}
	foreach ([[404,'media_not_found'],[403,'media_network_denied']] as [$code,$error]) {
		$result = SlsLocalWebProbe::mediaAccess([], [['status'=>$code,'headers'=>['X-SLS-Media-Policy: 1'], 'body'=>json_encode(['error'=>$error])]]);
		check($result['ok'], 'Healthy media gate was not recognized.');
	}
	check(!SlsLocalWebProbe::mediaAccess([], [['status'=>404,'headers'=>[], 'body'=>'Not found']])['ok'], 'Static Apache 404 falsely proved media policy enforcement.');
	check(!SlsLocalWebProbe::mediaAccess([], [['status'=>404,'headers'=>['X-SLS-Media-Policy: 1'], 'body'=>'{"error":"other","error":"media_not_found"}']])['ok'], 'Ambiguous duplicate-key media response proved policy enforcement.');
	$result = SlsLocalWebProbe::mediaAccess([], [['status'=>503,'headers'=>['X-SLS-Media-Policy: 1'], 'body'=>'{"error":"media_access_configuration_unavailable"}']]);
	check(!$result['ok'] && str_contains($result['message'], 'protected configuration'), 'Policy read error was not actionable.');
	check(!SlsLocalWebProbe::mediaAccess(['media_access'=>null], [])['ok'], 'Malformed policy passed readiness.');
	foreach ([null,['status'=>[],'headers'=>['X-SLS-Media-Policy: 1'],'body'=>'{}'],['status'=>404,'headers'=>[['X-SLS-Media-Policy: 1']],'body'=>'{}']] as $observation) {
		check(!SlsLocalWebProbe::mediaAccess([],[$observation])['ok'],'Malformed media observation was accepted or escaped bounded failure.');
	}
	echo "Local Apache discovery, custom-port authentication, loopback pinning, Host/SNI, request bounds, media policy and invalid-input fixtures passed.\n";
}
