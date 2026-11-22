<?php
namespace FreePBX\modules {
    function exec($command,&$output,&$status){$output=[];$status=1;}
    function file_get_contents($url,$includePath,$context,$offset,$length){throw new \RuntimeException('No request may occur without native route authority');}
}
namespace {
    require_once dirname(__DIR__).'/slsmassnotifyserver/LocalWebProbe.php';
    require_once dirname(__DIR__).'/slsmassnotifyserver/api/sls-mass-notify/media-policy.php';
    try{$result=FreePBX\modules\SlsLocalWebProbe::mediaAccess([]);}
    catch(Throwable $error){fwrite(STDERR,"Unavailable native authority must return a bounded media diagnostic, not abort readiness.\n");exit(1);}
    if(($result['ok']??true)!==false||!str_contains(strtolower($result['message']??''),'root-assisted')){fwrite(STDERR,"Media readiness must explain the required root-assisted route check.\n");exit(1);}
    echo "Unavailable native route authority remains a safe media-readiness result.\n";
}
