<?php
/** Inert transport boundary; native socket/TLS behavior has separate fixtures. */
namespace FreePBX\modules;
function curl_init($url) { return (object)['url'=>$url,'options'=>[]]; }
function curl_setopt_array($handle, $options) { $handle->options=$options; return true; }
function curl_exec($handle) {
    $body=isset($GLOBALS['localWebCurlObserver'])
        ? ($GLOBALS['localWebCurlObserver'])($handle->url,$handle->options) : '{}';
    foreach (["HTTP/1.1 200 OK\r\n", 'Content-Length: '.strlen($body)."\r\n", "\r\n"] as $line) {
        if (($handle->options[CURLOPT_HEADERFUNCTION])($handle,$line)!==strlen($line)) { return false; }
    }
    return ($handle->options[CURLOPT_WRITEFUNCTION])($handle,$body)===strlen($body);
}
function curl_getinfo($handle, $option) { return $option===CURLINFO_RESPONSE_CODE ? 200 : null; }
function curl_errno($handle) { return 0; }
function curl_close($handle) {}
