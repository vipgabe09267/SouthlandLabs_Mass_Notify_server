#!/usr/bin/python3
"""Verify the loopback prerequisite probe through an isolated PHP HTTP handler."""
import json
import xml.etree.ElementTree as ET
import importlib.util
import os
import pwd
from pathlib import Path
import socket
import tempfile
import shutil
import subprocess
import time
import unittest
import urllib.error
import urllib.request

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or any(
    os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in (None, '', os.readlink('/proc/self/ns/' + kind))
    for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]
):
    raise SystemExit('Use the private fixture runner; served-PHP isolation verification failed.')

ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = ET.parse(ROOT / 'slsmassnotifyserver/module.xml').findtext('version')


class ServedPhp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace=tempfile.TemporaryDirectory(prefix='sls-served-php-')
        cls.web=Path(cls.workspace.name);cls.web.chmod(0o755)
        shutil.copytree(ROOT/'slsmassnotifyserver',cls.web,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        cls.web.chmod(0o755)
    @classmethod
    def tearDownClass(cls):cls.workspace.cleanup()
    def prerequisite_failure(self, disabled=False):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        command=['php']
        if disabled: command.extend(['-d','disable_functions='+(disabled if isinstance(disabled,str) else 'exec,proc_open')])
        command.extend(['-S',f'127.0.0.1:{port}','-t',str(self.web)])
        if disabled: command=['/usr/sbin/runuser','-u','asterisk','--']+command
        process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            url=f'http://127.0.0.1:{port}/api/sls-mass-notify/?sls_installer_runtime=1'
            for unused in range(50):
                try:
                    with urllib.request.urlopen(url,timeout=2) as response:
                        self.fail('Unsafe served runtime passed preflight')
                except urllib.error.HTTPError as error:
                    self.assertEqual(error.code,503);body=json.loads(error.read());break
                except OSError: time.sleep(.05)
            else: self.fail('Isolated PHP prerequisite handler did not start')
            self.assertEqual(body['probe'],'sls_served_php_v1');self.assertFalse(body['ok'])
            if isinstance(disabled,str): self.assertIn(disabled+'_enabled',body['missing'])
            elif disabled: self.assertTrue({'exec_enabled','proc_open_enabled'}<=set(body['missing']))
            else: self.assertIn('web_runtime_must_run_as_asterisk',body['missing'])
            self.assertNotIn('uid',body);self.assertNotIn('username',body)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

    def test_root_php_runtime_is_rejected(self): self.prerequisite_failure()
    def test_disabled_process_functions_are_rejected(self): self.prerequisite_failure(True)

    def test_disabled_native_cron_functions_are_rejected_by_served_runtime(self):
        for function in ('sem_get','sem_acquire','sem_remove'):
            with self.subTest(function=function):self.prerequisite_failure(function)

    def test_cli_cron_capability_is_checked_before_bootstrap_or_activation(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        gate=source[source.index('verify_php_security_versions_before_mutation() {'):source.index('\nverify_freepbx_web_response()')]
        for function in ('sem_get','sem_acquire','sem_remove'):
            definition=gate.replace('/usr/bin/php -r','/usr/bin/php -d disable_functions='+function+' -r',1)
            script='set -euo pipefail\nlog(){ printf "%s\n" "$*"; }\n'+definition+'\nSTAGING_DIR="$1";MODULE=slsmassnotifyserver;SERVED_PHP_PROFILES="";verify_php_security_versions_before_mutation\nprintf MUTATION-REACHED\n'
            result=subprocess.run(['/bin/bash','-c',script,'fixture',str(ROOT)],capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertNotIn('MUTATION-REACHED',result.stdout)
            self.assertIn(function,result.stdout+result.stderr)

    def test_probe_is_read_only_get_and_rejects_forwarded_requests(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        process = subprocess.Popen(['/usr/sbin/runuser','-u','asterisk','--','php','-S',f'127.0.0.1:{port}','-t',str(self.web)],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            url = f'http://127.0.0.1:{port}/api/sls-mass-notify/?sls_installer_runtime=1'
            def fetch(method='GET', headers=None):
                request = urllib.request.Request(url,method=method,headers=headers or {})
                try: response = urllib.request.urlopen(request,timeout=2)
                except urllib.error.HTTPError as error: response = error
                with response: return response.status, json.loads(response.read()), response.headers
            for unused in range(50):
                try: status, body, headers = fetch(); break
                except (OSError,ValueError): time.sleep(.05)
            else: self.fail('Isolated PHP HTTP handler did not start')
            self.assertEqual(status,200)
            self.assertEqual(body['probe'],'sls_served_php_v1');self.assertTrue(body['ok']);self.assertEqual(body['missing'],[])
            self.assertTrue(body['runtime_account_ok']);self.assertRegex(body['php_version'],r'^8\.[0-9]+\.[0-9]+')
            self.assertEqual(body['php_sapi'],'cli-server')
            self.assertEqual(body['module_version'],CURRENT_VERSION)
            self.assertTrue(all(value is True for value in body['extensions'].values()))
            self.assertTrue(all(value is True for value in body['functions'].values()))
            self.assertEqual(set(body),{'probe','ok','missing','module_version','php_version','php_sapi','runtime_account_ok','extensions','functions'})
            self.assertEqual(headers['Cache-Control'],'no-store')
            spec=importlib.util.spec_from_file_location('served_php_doctor_fixture',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_doctor.py')
            doctor=importlib.util.module_from_spec(spec);spec.loader.exec_module(doctor)
            evidence=doctor.served_php_probe([('http','127.0.0.1',port,'localhost')])
            self.assertTrue(evidence['ok']);self.assertEqual(evidence['php_version'],body['php_version'])
            self.assertEqual(evidence['php_sapi'],'cli-server');self.assertTrue(evidence['runtime_account_ok'])
            for method, forwarded in [('POST',{}),('GET',{'Forwarded':'for=192.0.2.1'}),
                                      ('GET',{'X-Forwarded-For':'192.0.2.1'})]:
                status, body, unused = fetch(method,forwarded)
                self.assertNotEqual(status,200)
                self.assertNotIn('probe',body)
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


if __name__ == '__main__': unittest.main()
