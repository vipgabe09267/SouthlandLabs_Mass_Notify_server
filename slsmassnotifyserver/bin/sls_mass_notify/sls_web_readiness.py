#!/usr/bin/python3
"""Bounded, credential-free inspection of the local FreePBX web response."""
from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import sys
import threading
import time

sys.dont_write_bytecode = True
MAX_BODY = 1048576


def targets(dump):
    result = []
    for line in dump[:262144].splitlines():
        match = re.match(r'^\s*(?:(\*|[0-9.]+|\[[0-9a-f:]+\]):([0-9]+)\s+|port\s+([0-9]+)\s+namevhost\s+)([^\s(]+)', line, re.I)
        if not match:
            continue
        port, host = int(match[2] or match[3]), match[4].lower()
        if not 1 <= port <= 65535 or not re.fullmatch(r'(?=.{1,253}$)[a-z0-9.-]+', host):
            continue
        address = '::1' if (match[1] or '').startswith('[') else '127.0.0.1'
        for scheme in (('https', 'http') if port in (443, 8443) else ('http', 'https')):
            target = (scheme, address, port, host)
            if target not in result:
                result.append(target)
        if len(result) >= 32:
            break
    for target in [('http', '127.0.0.1', 80, '127.0.0.1'), ('https', '127.0.0.1', 443, '127.0.0.1')]:
        if target not in result:
            result.append(target)
    return result


class LoopbackTLS(http.client.HTTPSConnection):
    def __init__(self, address, port, host, timeout):
        # This identifies a local web handler; it does not certify the public
        # certificate chain. No credentials, DNS, proxies or redirects are used.
        super().__init__(address, port, timeout=timeout, context=ssl._create_unverified_context())
        self.server_name = host

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.server_name)
        except BaseException:
            sock.close()
            raise


def probe(candidates, timeout=4):
    deadline = time.monotonic() + timeout
    failure = {'available': False, 'ok': False, 'failure_code': 'freepbx_web_probe_unavailable', 'authenticated': False}
    limited = None
    for scheme, address, port, host in candidates:
        if address not in ('127.0.0.1', '::1') or scheme not in ('http', 'https') or type(port) is not int or not 1 <= port <= 65535:
            continue
        if not isinstance(host, str) or not re.fullmatch(r'(?=.{1,253}$)[a-z0-9.-]+', host):
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection = timer = None
        try:
            connection = LoopbackTLS(address, port, host, min(.8, remaining)) if scheme == 'https' else http.client.HTTPConnection(address, port, timeout=min(.8, remaining))
            connection.connect()
            def expire(expired_socket=connection.sock):
                try: expired_socket.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: expired_socket.close()
                except OSError: pass
            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            connection.request('GET', '/admin/config.php', headers={'Host': host + ':' + str(port), 'Accept': 'text/html', 'Connection': 'close'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308, 401, 403):
                limited = {'available': True, 'ok': True, 'http_status': response.status, 'access_limited': True, 'authenticated': False}
                continue
            if response.status != 200:
                continue
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_web_response_oversized', 'authenticated': False}
                continue
            prefix = ' '.join(re.sub(r'<[^>]{0,512}>', ' ', raw[:16384].decode('utf-8', 'replace')).lower().split())
            if re.search(r'\bscript error:.{0,200}ioncube.{0,200}(?:loader|encoded)', prefix):
                failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_vendor_loader_unavailable', 'authenticated': False}
                continue
            if re.search(br'<!doctype\s+html\b|<html(?:\s|>)', raw.lower()):
                return {'available': True, 'ok': True, 'http_status': 200, 'authenticated': False}
            failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_web_response_not_html', 'authenticated': False}
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            if timer is not None: timer.cancel()
            if connection is not None: connection.close()
    return failure if failure['available'] or limited is None else limited


def main():
    if len(sys.argv) != 1:
        raise SystemExit('Supply the native Apache virtual-host dump on stdin; no arguments are accepted.')
    raw = sys.stdin.buffer.read(262145)
    if len(raw) > 262144:
        raise SystemExit('The native Apache virtual-host inventory exceeds its inspection bound.')
    value = probe(targets(raw.decode('utf-8', 'replace')))
    print(json.dumps(value, sort_keys=True))
    if not value['ok']:
        print('FreePBX web readiness failed: ' + value['failure_code'] + '. Check the served PHP handler and vendor ionCube loader before installing SLL; no web response body or credentials were logged.', file=sys.stderr)
    return 0 if value['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
