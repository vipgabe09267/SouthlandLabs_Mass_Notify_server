#!/usr/bin/python3
"""Native private TCP/TLS and response phases share one diagnostic deadline."""
import contextlib
import importlib.util
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
from unittest.mock import patch

for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered'
            or os.environ.get('SLS_TEST_PARENT_' + label + '_NS')
            in (None, '', os.readlink('/proc/self/ns/' + kind))):
        raise SystemExit('Use the official isolated runner; no listener was opened.')

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def load(name):
    spec = importlib.util.spec_from_file_location('deadline_' + name, BIN / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WEB = load('sls_web_readiness')
DOCTOR = load('sls_install_doctor')
HOST = 'pbx.deadline.invalid'
HTML = b'<!doctype html><html><form id="loginform"></form></html>'


@contextlib.contextmanager
def listener(context, body, *, tls=True, handshake_delay=0, response_delay=0,
             status=200, trickle=False):
    stopping = threading.Event()
    ready = threading.Event()
    requests = []
    errors = []
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0)); server.listen(1); server.settimeout(.05)

    def serve():
        active = None
        try:
            while not stopping.is_set():
                try: active, _ = server.accept(); break
                except socket.timeout: continue
            if active is None: return
            active.settimeout(1)
            if tls:
                # Delay the native server handshake only after ClientHello is
                # pending; a separate TCP phase can consume the same budget.
                active.recv(1, socket.MSG_PEEK)
                ready.set()
                if stopping.wait(handshake_delay): return
                active = context.wrap_socket(active, server_side=True)
            else:
                ready.set()
            request = bytearray()
            while b'\r\n\r\n' not in request and len(request) <= 16384:
                block = active.recv(4096)
                if not block: return
                request.extend(block)
            requests.append(bytes(request))
            if stopping.wait(response_delay): return
            header = (b'HTTP/1.1 ' + str(status).encode() + b' Fixture\r\nContent-Length: '
                      + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n')
            active.sendall(header)
            if trickle:
                width = max(1, (len(body) + 14) // 15)
                for index in range(0, len(body), width):
                    active.sendall(body[index:index + width])
                    if index + width < len(body) and stopping.wait(.035): return
            else:
                active.sendall(body)
        except (OSError, ssl.SSLError):
            # Deadline termination deliberately closes an active native socket.
            pass
        except BaseException as error:
            errors.append(repr(error))
        finally:
            if active is not None: active.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield ('https' if tls else 'http', '127.0.0.1', server.getsockname()[1], HOST), requests, ready
    finally:
        stopping.set(); server.close(); thread.join(timeout=2)
        if thread.is_alive(): raise AssertionError('Private fixture listener did not terminate')
        if errors: raise AssertionError(errors)


class WebReadinessDeadline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='sls-web-deadline-', dir='/run')
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-days', '1', '-subj', '/CN=' + HOST, '-keyout', str(root / 'key'), '-out', str(root / 'cert')],
            check=True, capture_output=True, timeout=10)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(root / 'cert', root / 'key')

    def payload(self, entry):
        if entry == 'readiness': return HTML
        return json.dumps({'probe': 'sls_served_php_v1', 'ok': True, 'php_version': '8.2.35',
            'php_sapi': 'fpm-fcgi', 'runtime_account_ok': True,
            'extensions': dict.fromkeys(DOCTOR.PHP_EXTENSIONS, True),
            'functions': dict.fromkeys(DOCTOR.PHP_FUNCTIONS, True)}).encode()

    @staticmethod
    def probe(entry, target, timeout):
        return WEB.probe([target], timeout) if entry == 'readiness' else DOCTOR.served_php_probe([target], timeout)

    def test_slow_native_tls_then_continuous_body_cannot_renew_original_budget(self):
        for entry in ('readiness', 'doctor'):
            with self.subTest(entry=entry), listener(self.context, self.payload(entry), handshake_delay=.35,
                                                   trickle=True) as (target, calls, hello):
                start = time.monotonic()
                value = self.probe(entry, target, .65)
                elapsed = time.monotonic() - start
                self.assertTrue(hello.is_set(), 'Control did not reach the native TLS handshake')
                self.assertEqual(len(calls), 1, 'Control did not reach the actual response-body phase')
                self.assertFalse(value['ok'], 'A valid response arriving after the original deadline was accepted: ' + str(elapsed))
                self.assertLess(elapsed, .95, 'TLS and body phases renewed the shared .65-second budget')

    def test_readiness_late_access_limited_headers_do_not_establish_health(self):
        with listener(self.context, b'', handshake_delay=.35, response_delay=.35,
                      status=302) as (target, calls, hello):
            value = self.probe('readiness', target, .65)
            self.assertTrue(hello.is_set()); self.assertEqual(len(calls), 1)
            self.assertFalse(value['ok'], 'Late redirect headers were accepted after the original deadline')

    def test_tcp_and_tls_phases_do_not_each_receive_the_original_budget(self):
        native_socket = socket.socket

        class SlowConnect(native_socket):
            def connect(self, address):
                # Deterministic TCP-phase latency around a genuine private TCP
                # connection; TLS handshake and all response I/O remain native.
                result = super().connect(address)
                time.sleep(.35)
                return result

        for entry in ('readiness', 'doctor'):
            with self.subTest(entry=entry), listener(self.context, self.payload(entry),
                                                   handshake_delay=.4) as (target, calls, hello):
                with patch.object(socket, 'socket', SlowConnect):
                    start = time.monotonic()
                    value = self.probe(entry, target, .65)
                    elapsed = time.monotonic() - start
                self.assertTrue(hello.is_set(), 'TLS handshake phase was not exercised')
                self.assertFalse(value['ok'], 'TCP and TLS each received a fresh deadline: ' + str(elapsed))
                self.assertLess(elapsed, .95)

    def test_finished_body_delivered_to_caller_after_deadline_is_not_accepted(self):
        read = WEB.http.client.HTTPResponse.read

        def delayed_return(response, *args, **kwargs):
            raw = read(response, *args, **kwargs)
            time.sleep(.2)  # Scheduler/consumer delay after native complete read.
            return raw

        for entry in ('readiness', 'doctor'):
            with self.subTest(entry=entry), listener(self.context, self.payload(entry),
                                                   tls=False) as (target, calls, unused):
                with patch.object(WEB.http.client.HTTPResponse, 'read', delayed_return):
                    value = self.probe(entry, target, .12)
                self.assertEqual(len(calls), 1)
                self.assertFalse(value['ok'], 'Completed data was accepted after its original deadline')

    def test_candidates_share_the_same_original_tls_and_body_deadline(self):
        for entry in ('readiness', 'doctor'):
            with self.subTest(entry=entry), listener(self.context, b'<html>unrelated</html>',
                                                   handshake_delay=.3) as (first, first_calls, unused):
                with listener(self.context, self.payload(entry), handshake_delay=.25,
                              trickle=True) as (second, second_calls, unused):
                    start = time.monotonic()
                    value = (WEB.probe([first, second], .65) if entry == 'readiness'
                             else DOCTOR.served_php_probe([first, second], .65))
                    elapsed = time.monotonic() - start
                    self.assertFalse(value['ok'], 'A later candidate renewed the original deadline')
                    self.assertEqual((len(first_calls), len(second_calls)), (1, 1))
                    self.assertLess(elapsed, .95)

    def test_shared_transport_rejects_unsafe_inputs_before_opening_any_socket(self):
        base = dict(scheme='http', address='127.0.0.1', port=8000, host=HOST,
                    path='/admin/config.php', accept='text/html', deadline=time.monotonic()+1,
                    limit=4096, statuses=(200,))
        cases = [{'address': '192.0.2.1'}, {'port': True}, {'port': 65536},
                 {'scheme': 'file'}, {'host': HOST+'\r\nAuthorization: forbidden'},
                 {'host': 'x'*254}, {'path': 'https://public.invalid/escape'},
                 {'path': '/admin/config.php\r\nCookie: forbidden'},
                 {'accept': 'text/html\r\nAuthorization: forbidden'},
                 {'deadline': float('inf')}, {'deadline': time.monotonic()-1},
                 {'limit': 1048577}, {'statuses': (True,)}]
        with patch.object(socket, 'socket', side_effect=AssertionError('An invalid request opened a socket')):
            for change in cases:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    WEB.read_response(**dict(base, **change))

    def test_fast_native_http_tls_and_access_limited_controls_stay_valid(self):
        for entry in ('readiness', 'doctor'):
            for tls in (False, True):
                with self.subTest(entry=entry, tls=tls), listener(self.context, self.payload(entry),
                                                               tls=tls) as (target, calls, unused):
                    value = self.probe(entry, target, .65)
                    self.assertTrue(value['ok'], value)
                    self.assertEqual(len(calls), 1)
                    request = calls[0].lower()
                    self.assertIn(('host: ' + HOST + ':' + str(target[2])).encode(), request)
                    self.assertNotIn(b'authorization:', request)
                    self.assertNotIn(b'cookie:', request)
        for status in (302, 401, 403):
            with self.subTest(status=status), listener(self.context, b'', status=status) as (target, calls, unused):
                value = self.probe('readiness', target, .65)
                self.assertTrue(value['ok']); self.assertTrue(value['access_limited'])
                self.assertFalse(value['authenticated'])


if __name__ == '__main__':
    unittest.main()
