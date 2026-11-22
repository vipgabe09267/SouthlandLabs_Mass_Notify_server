#!/usr/bin/python3
"""Real buffered HTTP trickle must obey the complete download wall deadline."""
import http.server
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('v020_download',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_upgrade_trust.py')
UPGRADE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(UPGRADE)
URL='https://mirror.freepbx.org/modules/packages/framework/framework-17.0.33.tgz.gpg'


class DownloadDeadline(unittest.TestCase):
    def setUp(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*unused):pass
            def do_GET(self):
                body=b'complete fixture bytes' if self.path=='/fast' else b'x'*128
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:
                    if self.path=='/slow':
                        for byte in body:
                            self.wfile.write(bytes((byte,)));self.wfile.flush();time.sleep(0.02)
                    else:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.temp=tempfile.TemporaryDirectory(prefix='sls-v020-download-',dir='/run')
        self.addCleanup(self.temp.cleanup)
        self.destination=Path(self.temp.name)/'download'
        self.real_opener=urllib.request.build_opener(UPGRADE.Redirects())

    def opener(self,path):
        real=self.real_opener;port=self.server.server_port
        class LocalTransport:
            def open(self,request,timeout):
                # Only transport is redirected; actual urllib buffering, body
                # limits and product deadline logic remain unchanged.
                return real.open(urllib.request.Request('http://127.0.0.1:'+str(port)+path,
                    headers=dict(request.header_items())),timeout=timeout)
        return LocalTransport()

    def test_continuous_real_http_bytes_cannot_extend_the_total_deadline(self):
        started=time.monotonic()
        with patch.object(UPGRADE,'DOWNLOAD_DEADLINE_SECONDS',0.2,create=True),\
             patch.object(UPGRADE.urllib.request,'build_opener',return_value=self.opener('/slow')):
            with self.assertRaisesRegex(UPGRADE.UpgradeError,'three minutes|deadline'):
                UPGRADE.download(URL,self.destination,1024)
        self.assertLess(time.monotonic()-started,1.0,'A buffered read exceeded the configured complete-operation deadline')

    def test_complete_body_stays_exact_and_size_limits_stay_enforced(self):
        with patch.object(UPGRADE,'DOWNLOAD_DEADLINE_SECONDS',2.0,create=True),\
             patch.object(UPGRADE.urllib.request,'build_opener',return_value=self.opener('/fast')):
            UPGRADE.download(URL,self.destination,64)
        self.assertEqual(self.destination.read_bytes(),b'complete fixture bytes')
        self.destination.unlink()
        with patch.object(UPGRADE,'DOWNLOAD_DEADLINE_SECONDS',2.0,create=True),\
             patch.object(UPGRADE.urllib.request,'build_opener',return_value=self.opener('/fast')):
            with self.assertRaises(UPGRADE.UpgradeError):UPGRADE.download(URL,self.destination,4)

    def test_unapproved_origin_is_rejected_before_transport_or_output(self):
        with patch.object(UPGRADE.urllib.request,'build_opener') as opener:
            with self.assertRaises(UPGRADE.UpgradeError):
                UPGRADE.download('http://127.0.0.1/forbidden',self.destination,1024)
            opener.assert_not_called()
        self.assertFalse(self.destination.exists())


if __name__=='__main__':unittest.main()
