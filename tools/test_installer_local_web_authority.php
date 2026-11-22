<?php
/** Request-boundary regressions: fake native inventories and inert dummy headers. */
namespace FreePBX\modules {
    function exec($command,&$output,&$status){$output=explode("\n",str_contains($command,'DUMP_CONFIG')?($GLOBALS['config_dump']??''):($GLOBALS['vhost_dump']??''));$status=0;}
    require __DIR__.'/fixtures/local_web_curl.php';
    $GLOBALS['localWebCurlObserver']=static function($url,$options){$GLOBALS['requests'][]=[$url,$options];return '{}';};
}
namespace {
    require_once dirname(__DIR__).'/slsmassnotifyserver/LocalWebProbe.php';
    use FreePBX\modules\SlsLocalWebProbe;
    $GLOBALS['route_failures']=[];
    function routeCheck($condition,$message){if(!$condition){$GLOBALS['route_failures'][]=$message;}}
    function requestFixture($vhosts,$config){
        $GLOBALS['vhost_dump']=$vhosts;$GLOBALS['config_dump']=$config;$GLOBALS['requests']=[];
        try{iterator_to_array(SlsLocalWebProbe::responses('pbx.example.test','/api/sls-mass-notify/?resource=status',['Authorization: Bearer inert-test-only','Accept: application/json'],1,$vhosts,$config));}
        catch(RuntimeException $error){}
        return $GLOBALS['requests'];
    }
    $foreignBinding="192.0.2.80:8443 pbx.example.test (/etc/apache2/sites-enabled/pbx.conf:1)\n127.0.0.1:8443 unrelated.example.test (/etc/apache2/sites-enabled/unrelated.conf:1)\n";
    $foreignConfig="Listen 8443\n<VirtualHost 192.0.2.80:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n<VirtualHost 127.0.0.1:8443>\nServerName unrelated.example.test\nDocumentRoot /srv/unrelated\nSSLEngine on\n</VirtualHost>\n";
    routeCheck(requestFixture($foreignBinding,$foreignConfig)===[],'Credentials must not reach a loopback vhost merely because another bind address matches its hostname and port');
    $unrelated="*:80 unrelated.example.test (/etc/apache2/sites-enabled/unrelated.conf:1)\n";
    routeCheck(requestFixture($unrelated,"Listen 80\n<VirtualHost *:80>\nServerName unrelated.example.test\nDocumentRoot /srv/unrelated\n</VirtualHost>\n")===[],'An absent hostname authority must not fall back to standard-port credentials');
    $sameName="*:8443 pbx.example.test (/etc/apache2/sites-enabled/other.conf:1)\n";
    routeCheck(requestFixture($sameName,"Listen 8443\n<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /srv/unrelated\nSSLEngine on\n</VirtualHost>\n")===[],'A hostname match must also bind the actual canonical PBX document root');
    routeCheck(requestFixture($sameName,"Listen 8443\n<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\nProxyPass UNQUALIFIED_REMOTE_HANDLER\n</VirtualHost>\n")===[],'A redacted remote handler remains a blocking route override');
    $many='';$config='';
    for($port=18000;$port<18025;$port++){
        $many.='*:'.$port.' unrelated'.$port.".example.test (/etc/apache2/sites-enabled/other.conf:1)\n";
        $config.='Listen '.$port."\n<VirtualHost *:".$port.">\nServerName unrelated".$port.".example.test\nDocumentRoot /srv/other\n</VirtualHost>\n";
    }
    $many.="*:18443 pbx.example.test (/etc/apache2/sites-enabled/pbx.conf:1)\n";
    $config.="Listen 18443\n<VirtualHost *:18443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n</VirtualHost>\n";
    $requests=requestFixture($many,$config);
    routeCheck(count($requests)>0,'Bounded discovery must select actual PBX authority before limiting unrelated ports');
    foreach($requests as [$url,$options]){routeCheck(parse_url($url,PHP_URL_PORT)===18443&&$options[CURLOPT_HTTPHEADER][0]==='Host: pbx.example.test:18443','A bounded credential request escaped its actual PBX listener');}
    $requests=requestFixture('',"Listen 80\nServerName pbx.example.test\nDocumentRoot /var/www/html\n");
    routeCheck(count($requests)>0,'A canonical main-server PBX with explicit native authority must remain supported');
    foreach($requests as [$url,$options]){routeCheck(parse_url($url,PHP_URL_PORT)===80,'Main-server authority must not grant another undiscovered listener');}
    // Reproduce the actual server-level FreePBX redirect exemption and branding overrides.
    $exclusion='RewriteCond %{REQUEST_URI} !^/(api/(sipnotify|sls-mass-notify)|sls_mass_notify)(/|$)';
    $redirect='RewriteRule ^ UNQUALIFIED_REMOTE_HANDLER [R=308,L,NE]';
    $branding='RedirectMatch 307 "^/(?:admin/modules/slsmassnotifyserver|sls_mass_notify)/assets/logo\.png$" "/sls-branding/logo.png"';
    $optional='RedirectMatch 307 "^/admin/modules/pbxsentinel/logo(?:-source)?\.png$" "/sls-branding/logo.png"';
    $wellKnown='RewriteRule ^/\.(well-known|freepbx-known)/ - [H=text/plain,L]';
    $denyHidden='RewriteRule (^\.|/\.) - [F]';
    $select=static function(string $rules,string $path='/api/sls-mass-notify/?sls_installer_runtime=1') use($sameName):bool {
        $conf="Listen 8443\n<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\nSSLEngine on\n".$rules."\n</VirtualHost>\n";
        return (bool)SlsLocalWebProbe::targets('pbx.example.test',$sameName,$conf,$path);
    };
    $actual=implode("\n",[$branding,$optional,'RewriteCond UNKNOWN UNKNOWN [NC]','RewriteCond %{REQUEST_URI} !^/\.(well-known|freepbx-known)/',$exclusion,$redirect,$wellKnown,$denyHidden]);
    foreach(['/api/sls-mass-notify/?sls_installer_runtime=1','/api/sipnotify/desktop','/sls_mass_notify/installer-render-check-1234.png'] as $path) {
        routeCheck($select($actual,$path),'Native branding/challenge and excluded redirects blocked '.$path);
    }
    routeCheck($select($exclusion." [OR]\n".$exclusion."\n".$redirect),'Two demonstrably false OR alternatives should exclude the redirect');
    foreach([
        'missing-exemption'=>$redirect,
        'unbounded OR alternative'=>$exclusion." [OR]\nRewriteCond UNKNOWN UNKNOWN\n".$redirect,
        'unknown OR predecessor'=>"RewriteCond UNKNOWN UNKNOWN [OR]\n".$exclusion."\n".$redirect,
        'unknown condition semantics'=>$exclusion." [UNKNOWN]\n".$redirect,
        'trailing OR'=>$exclusion." [OR]\n".$redirect,
        'section boundary'=>"<Location /unrelated>\n".$exclusion."\n</Location>\n".$redirect,
        'filter boundary'=>$exclusion."\nSLSRewriteBoundary reset\n".$redirect,
        'orphaned OR at filter boundary'=>"RewriteCond UNKNOWN UNKNOWN [OR]\nSLSRewriteBoundary reset\n".$exclusion."\n".$redirect,
        'orphaned OR before nested rule'=>"RewriteCond UNKNOWN UNKNOWN [OR]\n<Location /elsewhere>\n".$wellKnown."\n</Location>\n".$exclusion."\n".$redirect,
        'exemption consumed by previous rule'=>$exclusion."\n".$wellKnown."\n".$redirect,
        'relative match context'=>"<Directory /var/www/html>\n".$exclusion."\n".$redirect."\n</Directory>",
        'proxy rewrite flags'=>$exclusion."\nRewriteRule ^ UNQUALIFIED_REMOTE_HANDLER [P,L]",
        'handler mutation'=>'RewriteRule ^ - [H=text/plain,L]',
        'nonliteral branding expression'=>'RedirectMatch 307 "^/(?!admin).*" "/elsewhere"',
        'URI lookahead'=>'RewriteCond %{REQUEST_URI} !^/(?=api/).*'."\n".$redirect,
        'unexpected redirect target'=>'RewriteRule ^ /elsewhere [L]',
        'unscoped catchall denial'=>'RewriteRule .* - [F,L]',
    ] as $case=>$rules) { routeCheck(!$select($rules),'Unproven rewrite gained authority: '.$case); }
    routeCheck(!$select($branding,'/sls_mass_notify/assets/logo.png'),'An exact branding match must remain blocked');
    routeCheck(!$select($optional,'/admin/modules/pbxsentinel/logo-source.png'),'An optional branding branch must remain blocked');
    routeCheck(!$select($wellKnown,'/.freepbx-known/status'),'A matching challenge handler must remain blocked');
    routeCheck(!$select($denyHidden,'/api/sls-mass-notify/.hidden'),'A matching hidden-file denial must remain blocked');
    routeCheck(!$select($actual,'/api/sls-mass-notify-other/'),'An adjacent prefix without a slash boundary gained authority');
    routeCheck(!$select('RedirectMatch 307 "^/api/sls-mass-notify/media\.php$" "/other"','/sls_mass_notify/installer-render-check-1234.png'),'The rewritten media PHP destination must also be checked');
    $media='/sls_mass_notify/installer-render-check-1234.png';
    routeCheck(!$select("<Location /api/sls-mass-notify/media.php>\nSetHandler UNQUALIFIED_REMOTE_HANDLER\n</Location>",$media),'A handler override at the internally rewritten media location must remain blocked');
    routeCheck(!$select("ProxyPass /api/sls-mass-notify/media.php UNQUALIFIED_REMOTE_HANDLER",$media),'A proxy override at the internally rewritten media location must remain blocked');
    $named="<VirtualHost *:8443>\nServerName pbx.example.test\nDocumentRoot /var/www/html\n</VirtualHost>\n";
    $other="<VirtualHost *:8443>\nServerName other.example.test\nDocumentRoot /srv/other\n</VirtualHost>\n";
    $unnamed=str_replace("ServerName other.example.test\n",'',$other);
    $nativeRows=static fn($first,$second)=>'*:8443 is a NameVirtualHost'."\n port 8443 namevhost ".$first." (/fixture/first.conf:1)\n port 8443 namevhost ".$second." (/fixture/second.conf:1)\n";
    $ordered=static fn($first,$second,$config)=>(bool)SlsLocalWebProbe::targets('pbx.example.test',$nativeRows($first,$second),"Listen 8443\n".$config);
    routeCheck(!$ordered('pbx.example.test','pbx.example.test',$unnamed.$named),'An earlier nameless non-PBX vhost can inherit the later explicit hostname');
    routeCheck(!$ordered('other.example.test','pbx.example.test',$named.$other),'Permuted native vhost order cannot prove selected document root');
    routeCheck($ordered('pbx.example.test','pbx.example.test',$named.$unnamed),'An explicit first native PBX host should retain authority');
    foreach(['RewriteCond UNKNOWN UNKNOWN [UNKNOWN]','RewriteCond %{REQUEST_URI} -U','RewriteCond %{LA-U:REQUEST_FILENAME} ^/','RewriteCond expr true'] as $opaque) {
        routeCheck(!$select($opaque."\n".$exclusion."\n".$redirect),'An opaque condition was hidden by a later false URI condition: '.$opaque);
    }
    routeCheck($select('AddHandler type-map var'),'Stock Debian type-map for .var cannot handle a verified PHP endpoint');
    routeCheck($select('AddHandler application/x-httpd-php .php'),'Canonical local PHP handler should retain authority');
    foreach(['AddHandler site-handler .php','AddHandler site-handler .PHP .other','AddHandler site-handler $unknown'] as $handler) {
        routeCheck(!$select($handler),'Unclassified handler may claim PHP endpoint: '.$handler);
    }
    routeCheck(!$select('AddHandler site-handler .png',$media),'AddHandler can claim generated PNG');
    routeCheck(!$select('AddHandler site-handler .php','/sls_mass_notify/with.a.name.png'),'AddHandler can claim internal media PHP handler');
    routeCheck(!$select('AddHandler site-handler .a','/sls_mass_notify/with.a.name.png'),'Apache mod_mime inspects multiple filename extensions');
    if($GLOBALS['route_failures']){foreach(array_unique($GLOBALS['route_failures']) as $failure){fwrite(STDERR,$failure."\n");}exit(1);}
    echo "Local requests require canonical PBX route, exact loopback binding and hostname authority before credentials.\n";
}
