#!/usr/bin/python3
"""Observe real pinned IdP HTTPS connections in the private network namespace."""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or os.environ.get('SLS_TEST_PARENT_NET_NS') in (None, '', os.readlink('/proc/self/ns/net')):
    raise SystemExit('Use the isolated fixture wrapper.')


class IPv6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _PinnedFixture:
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sls-idp-dualstack-')
        cls.directory = Path(cls.temp.name)
        for address in ('8.8.8.8/32', '2606:4700:4700::1111/128'):
            subprocess.run(['ip', 'addr', 'add', address, 'dev', 'lo'], check=True, capture_output=True, timeout=5)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-sha256', '-subj', '/CN=idp.example.test', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=DNS:idp.example.test', '-keyout', str(cls.directory/'key.pem'), '-out', str(cls.directory/'certificate.pem')], check=True, capture_output=True, timeout=15)
        cls.requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                cls.requests.append(self.path)
                body=b'{"ok":true}'
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        cls.servers=[];cls.threads=[]
        for server_type, address in ((http.server.ThreadingHTTPServer,'8.8.8.8'), (IPv6Server,'2606:4700:4700::1111')):
            server=server_type((address,0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cls.directory/'certificate.pem', cls.directory/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            cls.servers.append(server);cls.threads.append(thread)
        php='''<?php
namespace SLS\\MassNotify;
function dns_get_record($host,$flags){return array_map(static fn($ip)=>str_contains($ip,':')?['type'=>'AAAA','ipv6'=>$ip]:['type'=>'A','ip'=>$ip],$GLOBALS['dns_fixture']);}
require MODULE;
$value=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);$GLOBALS['dns_fixture']=$value['dns'];
$policy=['hosts'=>['idp.example.test'],'private_pins'=>$value['private_pins']??[],'tls'=>['ca_pem'=>$value['ca']]];
try{if(isset($value['inspect'])){echo json_encode(['addresses'=>EnterpriseIdentityHttp::pinnedAddresses('idp.example.test',$policy)]);exit;}$selected=EnterpriseIdentityHttp::pinnedAddress('idp.example.test',$policy);$reply=EnterpriseIdentityHttp::request('https://idp.example.test:'.$value['port'].'/fixture',$policy);echo json_encode(['selected'=>$selected,'response'=>$reply]);}
catch(\\Throwable $error){echo json_encode(['selected'=>$selected??null,'error'=>$error->getMessage()]);}
'''.replace('MODULE',repr(str(ROOT/'slsmassnotifyserver/EnterpriseIdentityHttp.php')))
        (cls.directory/'request.php').write_text(php)
        cls.observations=[]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown();server.server_close()
        for thread in cls.threads:
            thread.join(3)
        print('IDP_DESTINATION_OBSERVATIONS '+json.dumps(cls.observations),flush=True)
        cls.temp.cleanup()

    def request(self,label,addresses,server):
        before=len(self.requests)
        value={'dns':addresses,'port':self.servers[server].server_port,'ca':(self.directory/'certificate.pem').read_text()}
        result=subprocess.run(['php',str(self.directory/'request.php')],input=json.dumps(value),capture_output=True,text=True,check=True,timeout=15)
        self.assertEqual(result.stderr,'')
        record={'scenario':label,**json.loads(result.stdout),'requests_received':len(self.requests)-before}
        self.observations.append(record)
        return record



class PinnedFallback(_PinnedFixture,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        subprocess.run(['ip','addr','add','8.8.4.4/32','dev','lo'],check=True,capture_output=True,timeout=5)
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):
                pass
            def do_GET(self):
                cls.requests.append({'method':'GET','address':self.server.server_address[0]})
                body=b'{"ok":true}';self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                if length>4096:raise RuntimeError('Fixture input exceeded its bound')
                self.rfile.read(length)
                cls.requests.append({'method':'POST','address':self.server.server_address[0]})
                if self.path=='/accepted-close':
                    self.close_connection=True
                    return
                body=b'{"ok":true}';self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
        for server in cls.servers:
            server.RequestHandlerClass=Handler
        server=http.server.ThreadingHTTPServer(('8.8.4.4',cls.servers[0].server_port),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.directory/'certificate.pem',cls.directory/'key.pem')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        cls.servers.append(server);cls.threads.append(thread)
        php=(cls.directory/'request.php').read_text()
        original="$reply=EnterpriseIdentityHttp::request('https://idp.example.test:'.$value['port'].'/fixture',$policy);"
        assert original in php
        php=php.replace(original,"$reply=EnterpriseIdentityHttp::request('https://idp.example.test:'.$value['port'].($value['path']??'/fixture'),$policy,$value['method']??'GET',$value['form']??[]);")
        marker='require '
        location=php.index(marker)
        php=php[:location]+"function curl_getinfo($handle,$key){if($key===CURLINFO_PRIMARY_IP&&($GLOBALS['value']['spoof_primary']??false)){return '127.0.0.1';}return \\curl_getinfo($handle,$key);}\n"+php[location:]
        (cls.directory/'request.php').write_text(php)

    def request(self,label,addresses,server,**extra):
        before=len(self.requests)
        value={'dns':addresses,'port':self.servers[server].server_port,'ca':(self.directory/'certificate.pem').read_text(),**extra}
        started=time.monotonic()
        result=subprocess.run(['php',str(self.directory/'request.php')],input=json.dumps(value),capture_output=True,text=True,check=True,timeout=15)
        self.assertEqual(result.stderr,'')
        record={'scenario':label,**json.loads(result.stdout),'requests_received':len(self.requests)-before,'elapsed':round(time.monotonic()-started,3)}
        self.observations.append(record)
        return record

    def test_ipv4_available_but_first_ipv6_unavailable(self):
        result=self.request('IPv4 alternate after IPv6 failure',['8.8.8.8','2606:4700:4700::1111'],0)
        self.assertIn('response',result,result)
        self.assertEqual(result['response'],{'ok':True});self.assertEqual(result['requests_received'],1)

    def test_ipv6_available_but_first_ipv4_unavailable(self):
        result=self.request('IPv6 alternate after IPv4 failure',['1.1.1.1','2606:4700:4700::1111'],1)
        self.assertIn('response',result,result)
        self.assertEqual(result['response'],{'ok':True});self.assertEqual(result['requests_received'],1)

    def test_same_family_first_address_unavailable(self):
        result=self.request('IPv4 alternate after first address failure',['1.1.1.1','8.8.8.8'],0)
        self.assertIn('response',result,result)
        self.assertEqual(result['response'],{'ok':True});self.assertEqual(result['requests_received'],1)

    def test_all_unavailable_addresses_fail_within_one_deadline(self):
        result=self.request('all unavailable',['1.0.0.1','1.1.1.1'],0)
        self.assertIn('error',result);self.assertEqual(result['requests_received'],0)
        self.assertLess(result['elapsed'],12.5)

    def test_post_accepted_then_disconnected_is_never_replayed(self):
        result=self.request('POST accepted then response lost',['8.8.4.4','8.8.8.8'],0,method='POST',path='/accepted-close',form={'code':'inert-fixture-code'})
        self.assertIn('error',result);self.assertEqual(result['requests_received'],1)
        self.assertEqual(self.requests[-1],{'method':'POST','address':'8.8.4.4'})

    def test_tls_trust_and_public_key_pin_remain_required(self):
        for extra in ({'ca':''},{'pin':'sha256//'+base64.b64encode(b'x'*32).decode()}):
            with self.subTest(extra=extra):
                if 'pin' in extra:
                    php=(self.directory/'request.php').read_text()
                    updated=php.replace("'ca_pem'=>$value['ca']","'ca_pem'=>$value['ca'],'public_key_pin'=>$value['pin']??''")
                    (self.directory/'request.php').write_text(updated)
                result=self.request('TLS policy refuses invalid trust',['8.8.4.4','8.8.8.8'],0,**extra)
                self.assertIn('error',result);self.assertEqual(result['requests_received'],0)

    def test_connected_primary_address_must_belong_to_approved_set(self):
        result=self.request('unapproved reported primary',['8.8.8.8'],0,spoof_primary=True)
        self.assertIn('error',result);self.assertEqual(result['requests_received'],1)

    def test_single_family_control_requests_succeed(self):
        for addresses,server in ((['8.8.8.8'],0),(['2606:4700:4700::1111'],1)):
            with self.subTest(addresses=addresses):
                result=self.request('single family control',addresses,server)
                self.assertEqual(result['response'],{'ok':True})
                self.assertEqual(result['requests_received'],1)

    def test_mixed_private_public_answers_still_fail_closed(self):
        result=self.request('mixed public and private answer',['8.8.8.8','127.0.0.1'],0)
        self.assertIsNone(result['selected']);self.assertIn('error',result)
        self.assertEqual(result['requests_received'],0)

    def test_pinned_set_is_canonical_unique_and_deterministic(self):
        result=self.request('canonical vetted address set',['8.8.8.8','::ffff:1.1.1.1','1.1.1.1','2606:4700:4700::1111'],0,inspect=True)
        self.assertIn('addresses',result,result)
        self.assertEqual(result['addresses'],['1.1.1.1','2606:4700:4700::1111','8.8.8.8'])
        self.assertEqual(result['requests_received'],0)

    def test_exact_private_pin_remains_a_single_destination(self):
        result=self.request('exact private pin',['127.0.0.1','8.8.8.8'],0,inspect=True,private_pins=[{'host':'idp.example.test','ip':'10.20.30.40'}])
        self.assertIn('addresses',result,result)
        self.assertEqual(result['addresses'],['10.20.30.40'])
        self.assertEqual(result['requests_received'],0)

    def test_one_unsafe_dns_member_rejects_the_entire_set(self):
        for bad in ('127.0.0.1','169.254.169.254','::ffff:127.0.0.1','fc00::1'):
            with self.subTest(bad=bad):
                result=self.request('unsafe mixed address set',['8.8.8.8',bad],0,inspect=True)
                self.assertIn('error',result)
                self.assertEqual(result['requests_received'],0)



if __name__=='__main__':
    unittest.main()
