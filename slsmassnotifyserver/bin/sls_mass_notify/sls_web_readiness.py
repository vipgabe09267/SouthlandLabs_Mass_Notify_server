#!/usr/bin/python3
"""Bounded, credential-free inspection of the local FreePBX web response."""
from __future__ import annotations

import http.client
import json
import math
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


class LoopbackHTTP(http.client.HTTPConnection):
    def __init__(self, address, port, timeout, deadline):
        super().__init__(address, port, timeout=timeout)
        self.deadline = deadline
        self.auto_open = 0
        self._socket_lock = threading.Lock()
        self._expired = threading.Event()
        self._owned_sockets = []

    def phase_timeout(self):
        remaining = self.deadline - time.monotonic()
        if self._expired.is_set() or remaining <= 0:
            raise TimeoutError('Local web probe exceeded its total deadline')
        return min(self.timeout, remaining)

    def expire(self):
        with self._socket_lock:
            self._expired.set()
            # HTTPConnection may clear self.sock after headers while the
            # response file still owns its descriptor. Keep the actual sockets
            # so the guardian also interrupts that buffered body read.
            for active in self._owned_sockets:
                try: active.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: active.close()
                except OSError: pass

    def connect(self):
        with self._socket_lock:
            self.phase_timeout()
            self.sock = socket.socket(socket.AF_INET6 if self.host == '::1' else socket.AF_INET,
                                      socket.SOCK_STREAM)
            self._owned_sockets.append(self.sock)
        self.sock.settimeout(self.phase_timeout())
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(self.phase_timeout())


class LoopbackTLS(LoopbackHTTP):
    def __init__(self, address, port, host, timeout, deadline):
        # This identifies a local web handler; it does not certify the public
        # certificate chain. No credentials, DNS, proxies or redirects are used.
        super().__init__(address, port, timeout, deadline)
        self._context = ssl._create_unverified_context()
        self.server_name = host

    def connect(self):
        super().connect()
        with self._socket_lock:
            self.phase_timeout()
            # No handshake I/O occurs while the guardian is excluded. Publish
            # the wrapped socket before the first blocking TLS operation.
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_name,
                                                 do_handshake_on_connect=False)
            self._owned_sockets.append(self.sock)
        self.sock.settimeout(self.phase_timeout())
        self.sock.do_handshake()
        self.sock.settimeout(self.phase_timeout())


def read_response(scheme, address, port, host, path, accept, deadline, limit, statuses):
    """One credential-free loopback response under its caller's original deadline."""
    if (scheme not in ('http', 'https') or address not in ('127.0.0.1', '::1')
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(host, str) or not re.fullmatch(r'(?=.{1,253}$)[a-z0-9.-]+', host)
            or not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9/_?&=.-]{1,511}', path)
            or accept not in ('text/html', 'application/json')
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not 0 < deadline - time.monotonic() <= 30
            or type(limit) is not int or not 1 <= limit <= MAX_BODY
            or not isinstance(statuses, tuple) or not 1 <= len(statuses) <= 8
            or any(type(status) is not int or not 100 <= status <= 599 for status in statuses)):
        raise ValueError('Invalid bounded local web request')
    connection = (LoopbackTLS(address, port, host, .8, deadline) if scheme == 'https'
                  else LoopbackHTTP(address, port, .8, deadline))
    response = timer = None
    try:
        timer = threading.Timer(deadline - time.monotonic(), connection.expire)
        timer.daemon = True
        timer.start()
        connection.connect()
        connection.sock.settimeout(connection.phase_timeout())
        connection.request('GET', path, headers={'Host': host + ':' + str(port), 'Accept': accept,
                                                 'Connection': 'close'})
        response = connection.getresponse()
        connection.phase_timeout()
        raw = response.read(limit + 1) if response.status in statuses else b''
        connection.phase_timeout()
        return response.status, raw
    finally:
        if timer is not None: timer.cancel()
        connection.expire()
        if response is not None: response.close()
        connection.close()


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
        try:
            status, raw = read_response(scheme, address, port, host, '/admin/config.php',
                                        'text/html', deadline, MAX_BODY, (200,))
            if status in (301, 302, 303, 307, 308, 401, 403):
                limited = {'available': True, 'ok': True, 'http_status': status, 'access_limited': True, 'authenticated': False}
                continue
            if status != 200:
                continue
            if len(raw) > MAX_BODY:
                failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_web_response_oversized', 'authenticated': False}
                continue
            prefix = ' '.join(re.sub(r'<[^>]{0,512}>', ' ', raw[:16384].decode('utf-8', 'replace')).lower().split())
            if re.search(r'\bscript error:.{0,200}ioncube.{0,200}(?:loader|encoded)', prefix):
                failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_vendor_loader_unavailable', 'authenticated': False}
                continue
            html = raw.lower()
            # A cohost's generic HTTP 200 must not mask a later broken PBX.
            # Native Framework login IDs survive branding and translation.
            native_marker = re.search(br'\bid\s*=\s*[\"\'](?:loginform|login_admin|fpbx-container)[\"\']', html)
            if re.search(br'<!doctype\s+html\b|<html(?:\s|>)', html) and native_marker:
                if time.monotonic() >= deadline: break
                return {'available': True, 'ok': True, 'http_status': 200, 'authenticated': False}
            if failure.get('failure_code') != 'freepbx_vendor_loader_unavailable':
                failure = {'available': True, 'ok': False, 'http_status': 200, 'failure_code': 'freepbx_web_response_not_identified', 'authenticated': False}
        except (OSError, ValueError, http.client.HTTPException):
            pass
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
