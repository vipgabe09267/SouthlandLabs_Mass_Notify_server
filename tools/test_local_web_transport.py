#!/usr/bin/env python3
"""Native loopback transport bounds and routing; no PBX or real credentials."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered'
            or os.environ.get('SLS_TEST_PARENT_' + label + '_NS')
            in (None, '', os.readlink('/proc/self/ns/' + kind))):
        raise RuntimeError('Use the official private namespace wrapper; no listener was started.')

ROOT = Path(__file__).resolve().parents[1]
HOST = 'pbx.transport.invalid'
AUTH = 'Bearer SLL_NON_SECRET_TRANSPORT_FIXTURE'
PHP = r'''
require $argv[1];
$input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
$start=hrtime(true);$rows=[];$refused=false;
try {
    foreach (\FreePBX\modules\SlsLocalWebProbe::responses($input['host'],$input['path'],
        ['Authorization: Bearer SLL_NON_SECRET_TRANSPORT_FIXTURE','Accept: application/json'],
        $input['timeout'],$input['vhosts'],$input['config']) as $row) {
        $rows[]=['status'=>$row['status'],'header_count'=>count($row['headers']),
            'body_length'=>strlen($row['body']),'body'=>$row['body']!==''&&strlen($row['body'])<=128?$row['body']:''];
        if($input['first_only']) { break; }
    }
} catch (\RuntimeException $error) { $refused=true; }
echo json_encode(['responses'=>$rows,'refused'=>$refused,
    'elapsed_seconds'=>(hrtime(true)-$start)/1000000000],JSON_THROW_ON_ERROR);
'''


@contextlib.contextmanager
def listener(plan, tls=None, bind='127.0.0.1', port=0):
    calls = []
    stopping = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            self.close_connection = True
            calls.append({'host': self.headers.get('Host'), 'path': self.path,
                          'authorization': self.headers.get('Authorization')})
            try:
                plan(self.connection, stopping)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    server = http.server.ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port, calls
    finally:
        stopping.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def reply(body=b'{"fixture":"fast"}', status=b'200 OK', headers=()):
    def plan(connection, unused_stop):
        connection.sendall(b'HTTP/1.1 ' + status + b'\r\nContent-Length: '
            + str(len(body)).encode() + b'\r\nConnection: close\r\n'
            + b''.join(row + b'\r\n' for row in headers) + b'\r\n' + body)
    return plan


def body_trickle(chunks, delay):
    def plan(connection, stopping):
        connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(chunks).encode()
                           + b'\r\nConnection: close\r\n\r\n')
        for index in range(chunks):
            connection.sendall(b'x')
            if index + 1 < chunks and stopping.wait(delay):
                return
    return plan


def inventory(routes):
    vhosts, configuration = [], []
    for port, hostname, document_root, https in routes:
        binding = '127.0.0.1:' + str(port)
        vhosts.append(binding + ' ' + hostname + ' (/private/transport-fixture.conf:1)')
        configuration += ['Listen ' + binding, '<VirtualHost ' + binding + '>',
                          'ServerName ' + hostname, 'DocumentRoot ' + document_root]
        if https:
            configuration.append('SSLEngine on')
        configuration.append('</VirtualHost>')
    return '\n'.join(vhosts), '\n'.join(configuration)


def request(routes, timeout=1, first_only=False, host=HOST, environment=None, inventories=None):
    vhosts, configuration = inventory(routes) if inventories is None else inventories
    payload = {'host': host, 'path': '/api/sls-mass-notify/?resource=status',
               'timeout': timeout, 'first_only': first_only,
               'vhosts': vhosts, 'config': configuration}
    result = subprocess.run(['/usr/bin/php', '-r', PHP, str(ROOT / 'slsmassnotifyserver/LocalWebProbe.php')],
                            input=json.dumps(payload), capture_output=True, text=True,
                            timeout=42, env=environment)
    if result.returncode:
        raise AssertionError(result.stderr)
    if result.stderr:
        raise AssertionError('Transport emitted unexpected diagnostics: ' + result.stderr)
    return json.loads(result.stdout)


class LocalWebTransport(unittest.TestCase):
    def test_sole_nameless_vhost_preserves_configured_host_and_credentials_on_loopback(self):
        with listener(reply()) as (port, calls):
            native = '*:' + str(port) + ' 127.0.1.1 (/private/nameless-fixture.conf:1)\n'
            configuration = ('Listen 127.0.0.1:' + str(port) + '\n'
                + '<VirtualHost *:' + str(port) + '>\n'
                + 'DocumentRoot /var/www/html\n</VirtualHost>\n')
            result = request([], inventories=(native, configuration))
        self.assertFalse(result['refused'], 'A sole nameless canonical local vhost was refused')
        self.assertEqual(result['responses'][0]['status'], 200)
        self.assertEqual(calls, [{'host': HOST + ':' + str(port),
            'path': '/api/sls-mass-notify/?resource=status', 'authorization': AUTH}])

    def test_exact_address_decoy_receives_no_credentials_from_nameless_wildcard(self):
        with listener(reply()) as (port, decoy_calls):
            native = ('127.0.0.1:' + str(port)
                + ' decoy.transport.invalid (/private/exact-decoy.conf:1)\n'
                + '*:' + str(port) + ' 127.0.1.1 (/private/nameless-fixture.conf:1)\n')
            configuration = ('Listen 127.0.0.1:' + str(port) + '\n'
                + '<VirtualHost *:' + str(port) + '>\n'
                + 'DocumentRoot /var/www/html\n</VirtualHost>\n'
                + '<VirtualHost 127.0.0.1:' + str(port) + '>\n'
                + 'ServerName decoy.transport.invalid\n'
                + 'DocumentRoot /srv/unrelated\n</VirtualHost>\n')
            result = request([], inventories=(native, configuration))
        self.assertTrue(result['refused'])
        self.assertEqual(result['responses'], [])
        self.assertEqual(decoy_calls, [], 'Credentials reached the higher-priority exact-address decoy')

    def test_numeric_host_aliases_cannot_escape_the_qualified_loopback_listener(self):
        for alias in ('2130706434', '127.2', '0x7f000002'):
            with self.subTest(alias=alias), listener(reply()) as (port, qualified):
                with listener(reply(), bind='127.0.0.2', port=port) as (unused, wrong):
                    result = request([(port, alias, '/var/www/html', False)], host=alias)
                self.assertEqual(wrong, [], 'Credentials reached an unqualified numeric-host socket')
                self.assertEqual(len(qualified), 1, 'URL canonicalization bypassed the independently qualified socket')
                self.assertEqual(result['responses'][0]['status'], 200)

    def test_total_request_deadline_interrupts_continuous_body_trickle(self):
        with listener(body_trickle(41, 0.08)) as (port, calls):
            result = request([(port, HOST, '/var/www/html', False)])
        self.assertEqual(len(calls), 1)
        self.assertLess(result['elapsed_seconds'], 2.0, 'Continuous reads renewed the one-second request deadline')
        self.assertEqual(result['responses'], [{'status': 0, 'header_count': 0, 'body_length': 0, 'body': ''}])

    def test_total_request_deadline_interrupts_continuous_header_trickle(self):
        def slow_headers(connection, stopping):
            connection.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
            for unused in range(40):
                connection.sendall(b'x')
                if stopping.wait(0.08):
                    return
            connection.sendall(b'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        with listener(slow_headers) as (port, calls):
            result = request([(port, HOST, '/var/www/html', False)])
        self.assertEqual(len(calls), 1)
        self.assertLess(result['elapsed_seconds'], 2.0, 'Header bytes renewed the one-second request deadline')
        self.assertEqual(result['responses'], [{'status': 0, 'header_count': 0, 'body_length': 0, 'body': ''}])

    def test_candidate_requests_share_one_real_twenty_five_second_budget(self):
        # Each complete response takes eight seconds without any long idle gap.
        # Four fresh per-I/O timeouts take32s; the shared real budget is25s.
        with contextlib.ExitStack() as stack:
            servers = [stack.enter_context(listener(body_trickle(41, 0.2))) for unused in range(4)]
            result = request([(port, HOST, '/var/www/html', False) for port, unused in servers], timeout=10)
        self.assertLess(result['elapsed_seconds'], 27.0, 'Each candidate renewed the shared25-second budget')
        self.assertGreaterEqual(sum(row['status'] == 200 for row in result['responses']), 2)
        self.assertTrue(any(row['status'] == 0 for row in result['responses']))
        self.assertLessEqual(sum(len(calls) for unused, calls in servers), 4)

    def test_oversized_headers_or_body_never_return_a_successful_partial_response(self):
        cases = [
            reply(headers=[b'X-Fixture: x'] * 105),
            reply(headers=[b'X-Fixture: ' + b'x' * 32768]),
            reply(body=b'x' * 262145),
        ]
        for index, plan in enumerate(cases):
            with self.subTest(case=index), listener(plan) as (port, unused):
                result = request([(port, HOST, '/var/www/html', False)])
                self.assertEqual(result['responses'], [{'status': 0, 'header_count': 0, 'body_length': 0, 'body': ''}])
        with listener(reply(body=b'x' * 262144)) as (port, unused):
            result = request([(port, HOST, '/var/www/html', False)])
        self.assertEqual(result['responses'][0]['status'], 200)
        self.assertEqual(result['responses'][0]['body_length'], 262144)

    def test_redirects_are_observed_without_requesting_their_destination(self):
        with listener(reply()) as (other, wrong):
            with listener(reply(body=b'', status=b'302 Found',
                                headers=[b'Location: http://127.0.0.1:' + str(other).encode() + b'/must-not-follow'])) as (port, calls):
                result = request([(port, HOST, '/var/www/html', False)])
        self.assertEqual(result['responses'][0]['status'], 302)
        self.assertEqual(len(calls), 1)
        self.assertEqual(wrong, [])

    def test_matching_tls_route_preserves_host_sni_and_ignores_environment_proxies(self):
        with tempfile.TemporaryDirectory(prefix='sls-local-web-tls-') as name:
            root = Path(name)
            key, certificate = root / 'key.pem', root / 'certificate.pem'
            subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ec',
                '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                '-subj', '/CN=' + HOST, '-keyout', str(key), '-out', str(certificate)],
                check=True, capture_output=True, timeout=10)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            names = []
            context.set_servername_callback(lambda socket, name, unused: names.append(name))
            with listener(reply()) as (proxy, proxy_calls):
                with listener(reply(), tls=context) as (port, calls):
                    environment = dict(os.environ)
                    for field in ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
                        environment[field] = 'http://127.0.0.1:' + str(proxy)
                    environment['NO_PROXY'] = environment['no_proxy'] = ''
                    result = request([(port, HOST, '/var/www/html', True)], environment=environment)
            self.assertEqual(result['responses'][0]['status'], 200)
            self.assertEqual(names, [HOST])
            self.assertEqual(calls, [{'host': HOST + ':' + str(port),
                'path': '/api/sls-mass-notify/?resource=status', 'authorization': AUTH}])
            self.assertEqual(proxy_calls, [])

    def test_qualified_first_response_is_lazy_and_unrelated_cohost_gets_no_credentials(self):
        with listener(reply()) as (wrong_port, wrong):
            with listener(reply()) as (first_port, first):
                with listener(reply()) as (later_port, later):
                    routes = [(wrong_port, HOST, '/srv/unrelated', False),
                              (first_port, HOST, '/var/www/html', False),
                              (later_port, HOST, '/var/www/html', False)]
                    result = request(routes, first_only=True)
                    self.assertEqual(result['responses'][0]['status'], 200)
                    self.assertEqual(len(first), 1)
                    self.assertEqual(later, [])
                    self.assertEqual(wrong, [])
                    first.clear()
                    refused = request(routes, host='stale.transport.invalid')
                    self.assertTrue(refused['refused'])
                    self.assertEqual(refused['responses'], [])
                    self.assertEqual(first + later + wrong, [])


if __name__ == '__main__':
    unittest.main()
