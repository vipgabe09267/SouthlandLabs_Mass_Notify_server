#!/usr/bin/python3
"""Verify CAP connection fallback preserves pinned public DNS, TLS and transfer bounds."""
import http.server,json,os,socket,ssl,subprocess,tempfile,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if os.environ.get('SLS_TEST_NAMESPACE')!='entered' or os.environ.get('SLS_TEST_PARENT_NET_NS') in (None,'',os.readlink('/proc/self/ns/net')):raise SystemExit('Use the isolated wrapper.')
class CapPinnedFallback(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='sls-cap-target-');cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.received=[];cls.status=200;cls.body=b'<fixture/>'
  subprocess.run(['ip','addr','add','8.8.8.8/32','dev','lo'],check=True,capture_output=True,timeout=5)
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-subj','/CN=idp.example.test','-addext','subjectAltName=DNS:idp.example.test','-keyout',str(cls.root/'key.pem'),'-out',str(cls.root/'cert.pem')],check=True,capture_output=True,timeout=15)
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    cls.received.append(self.path);body=cls.body;self.send_response(cls.status);self.send_header('Content-Length',str(len(body)));self.send_header('Location','https://idp.example.test/redirect');self.end_headers()
    try:self.wfile.write(body)
    except OSError:pass
  cls.server=http.server.ThreadingHTTPServer(('8.8.8.8',443),Handler);cls.addClassCleanup(cls.server.server_close)
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cls.root/'cert.pem',cls.root/'key.pem');cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
  cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.addClassCleanup(cls.thread.join,3);cls.addClassCleanup(cls.server.shutdown)
  script=r'''<?php
namespace SLS\MassNotify;
function gethostbynamel($host){return $GLOBALS['input']['addresses'];}
function curl_version(){return isset($GLOBALS['input']['curl_version'])?['version_number'=>$GLOBALS['input']['curl_version']]:\curl_version();}
function curl_setopt_array($handle,$options){return \curl_setopt_array($handle,$options+[CURLOPT_CAINFO=>$GLOBALS['input']['ca']]);}
require MODULE;
$GLOBALS['input']=json_decode(stream_get_contents(STDIN),true,16,JSON_THROW_ON_ERROR);
try{echo json_encode(['body'=>AutomationInputs::fetch($GLOBALS['input']['url']??'https://idp.example.test/fixture')]);}
catch(\Throwable $error){echo json_encode(['error'=>$error->getMessage()]);}
'''.replace('MODULE',repr(str(ROOT/'slsmassnotifyserver/AutomationInputs.php')))
  (cls.root/'request.php').write_text(script);cls.results=[]
 @classmethod
 def tearDownClass(cls):print('CAP_DESTINATION_OBSERVATIONS '+json.dumps(cls.results),flush=True)
 def request(self,label,addresses,**extra):
  before=len(self.received);start=time.monotonic();value={'addresses':addresses,'ca':str(self.root/'cert.pem'),**extra}
  result=subprocess.run(['php',str(self.root/'request.php')],input=json.dumps(value),capture_output=True,text=True,check=True,timeout=12);self.assertEqual(result.stderr,'')
  row={'scenario':label,**json.loads(result.stdout),'requests':len(self.received)-before,'elapsed':round(time.monotonic()-start,3)};self.results.append(row);return row
 def test_healthy_control(self):
  r=self.request('healthy sole A',['8.8.8.8']);self.assertEqual(r['body'],'<fixture/>');self.assertEqual(r['requests'],1)
 def test_first_address_down_observation(self):
  r=self.request('unavailable first A with healthy alternate',['1.1.1.1','8.8.8.8']);self.assertIn('body',r,r);self.assertEqual(r['body'],'<fixture/>');self.assertEqual(r['requests'],1)
 def test_mixed_unsafe_refusal(self):
  r=self.request('mixed public and unsafe A',['8.8.8.8','127.0.0.1']);self.assertIn('error',r);self.assertEqual(r['requests'],0)
 def test_all_destinations_unavailable_stop_within_transfer_budget(self):
  r=self.request('all A unreachable',['1.1.1.1','1.0.0.1']);self.assertIn('error',r);self.assertEqual(r['requests'],0);self.assertLess(r['elapsed'],3.5)
 def test_invalid_trust_refuses_before_http(self):
  r=self.request('invalid TLS trust',['8.8.8.8'],ca='/dev/null');self.assertIn('error',r);self.assertEqual(r['requests'],0)
 def test_redirect_is_not_followed(self):
  type(self).status=302
  try:
   r=self.request('redirect refusal',['8.8.8.8']);self.assertIn('error',r);self.assertEqual(r['requests'],1)
  finally:type(self).status=200
 def test_response_limit_remains_one_mib(self):
  type(self).body=b'x'*1048577
  try:
   r=self.request('oversized body refusal',['8.8.8.8']);self.assertIn('error',r);self.assertEqual(r['requests'],1)
  finally:type(self).body=b'<fixture/>'
 def test_old_curl_refuses_multiple_pins_with_no_request(self):
  r=self.request('unsupported multi-address pin runtime',['8.8.8.8','1.1.1.1'],curl_version=0x073a00);self.assertIn('error',r);self.assertEqual(r['requests'],0)
 def test_unsafe_urls_and_oversized_dns_sets_refuse_before_http(self):
  for url in ['http://idp.example.test/fixture','https://127.0.0.1/fixture','https://idp.example.test:8443/fixture','https://idp.example.test/fixture#fragment']:
   with self.subTest(url=url):
    r=self.request('unsupported URL',['8.8.8.8'],url=url);self.assertIn('error',r);self.assertEqual(r['requests'],0)
  r=self.request('oversized DNS answer',[f'8.8.8.{n}' for n in range(1,34)]);self.assertIn('error',r);self.assertEqual(r['requests'],0)
if __name__=='__main__':unittest.main()
