#!/usr/bin/env python3
"""Prove native Telegram DH and RPC through the official WEB HTTPS carrier."""
import argparse
import base64
from collections import deque
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from vpn_env import env
from install_web_proxy import validate_hostname


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def frame(kind, stream=0, payload=b''):
    require(0 <= stream <= 0xFFFFFF and len(payload) <= 1024 * 1024, 'Invalid WEB frame bounds')
    return bytes([kind]) + stream.to_bytes(3, 'big') + struct.pack('!I', len(payload)) + payload


def frames(body):
    result = []
    while body:
        require(len(body) >= 8, 'Truncated WEB frame header')
        size = struct.unpack('!I', body[4:8])[0]
        require(size <= 1024 * 1024 and len(body) >= 8 + size, 'Truncated or oversized WEB frame')
        result.append((body[0], int.from_bytes(body[1:4], 'big'), body[8:8 + size]))
        require(len(result) <= 4096, 'Too many WEB frames')
        body = body[8 + size:]
    require(bool(result), 'Empty WEB frame batch')
    return result


def read_private(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
            'WEB probe input must be a small owner-only regular JSON file')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'Expected private WEB probe settings')
    parsed = urlsplit(value['origin'])
    require(parsed.scheme in ('http', 'https') and parsed.hostname and parsed.port
            and not parsed.username and not parsed.password and parsed.path in ('', '/')
            and not parsed.query and not parsed.fragment, 'Invalid WEB probe origin')
    require(isinstance(value['secret'], str) and re.fullmatch(r'dd[0-9a-f]{32}', value['secret']),
            'WEB native proof needs the padded backend secret')
    require(isinstance(value['hostname'], str) and isinstance(value['base_path'], str),
            'Missing WEB capability identity')
    validate_hostname(value['hostname'])
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9][A-Za-z0-9_-]*)*', value['base_path'])
            and len(value['base_path']) <= 128, 'Invalid WEB capability base path')
    if parsed.scheme == 'https':
        require(parsed.hostname == value['hostname'] and parsed.port == http.client.HTTPS_PORT,
                'Native WEB proof must verify the configured hostname on its standard HTTPS endpoint')
    else:
        require(ipaddress.ip_address(parsed.hostname).is_loopback,
                'Unencrypted WEB carrier proof is restricted to local prototypes')
    return value


class Carrier:
    def __init__(self, settings):
        self.settings = settings
        self.origin = urlsplit(settings['origin'])
        self.base = '/' + settings['base_path'].strip('/') + '/'
        self.token = ''
        self.up_sequence = 0
        self.down_cursor = '0'
        self.stopped = threading.Event()
        self.credit = 4 * 1024 * 1024
        self.credit_lock = threading.Condition()
        self.uploads = queue.Queue(maxsize=64)
        self.failure = deque(maxlen=1)

    def request(self, method, path, token='', body=None, extra=None):
        constructor = http.client.HTTPSConnection if self.origin.scheme == 'https' else http.client.HTTPConnection
        options = {'timeout': 35}
        if self.origin.scheme == 'https':
            options['context'] = ssl.create_default_context()
        connection = constructor(self.origin.hostname, self.origin.port, **options)
        headers = {'Host': self.settings['hostname'], 'Connection': 'close'}
        if body:
            headers['Content-Type'] = 'application/octet-stream'
        if token:
            headers['Authorization'] = 'Bearer ' + token
        headers.update(extra or {})
        try:
            connection.request(method, self.base + path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(2 * 1024 * 1024 + 1)
            require(len(data) <= 2 * 1024 * 1024, 'Oversized WEB carrier response')
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def start(self):
        context = ('tdesktop-web-proxy-bridge-v2\n' + self.settings['hostname']
                   + '\n' + self.settings['base_path'])
        digest = hmac.digest(bytes.fromhex(self.settings['secret']), context.encode(), 'sha256')
        capability = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        status, _, body = self.request('GET', '?bridge=' + capability)
        require(status == 200, 'WEB bridge unavailable')
        bootstrap = re.search(rb'bootstrap="([A-Za-z0-9_-]{43})"', body)
        require(bootstrap is not None, 'WEB bridge did not contain its one-shot bootstrap')
        status, headers, body = self.request('POST', 'api/v1/session', bootstrap[1].decode(), frame(0x10, 0, b'\x01'))
        require(status == 200 and headers.get('X-Carrier-Mode') == 'https'
                and frames(body) == [(0x11, 0, b'')], 'WEB carrier session was rejected')
        self.token = headers.get('X-Session-Token', '')
        require(re.fullmatch(r'[A-Za-z0-9_-]{43}', self.token), 'Invalid WEB session token')

    def upload(self, body):
        self.up_sequence += 1
        status, headers, _ = self.request('POST', 'api/v1/up', self.token, body,
                                          {'X-Up-Seq': str(self.up_sequence)})
        require(status == 204 and headers.get('X-Up-Ack') == str(self.up_sequence),
                'WEB carrier upload was not acknowledged')

    def receive(self, local):
        while not self.stopped.is_set():
            status, headers, body = self.request('POST', 'api/v1/down', self.token, b'',
                                                {'X-Down-Cursor': self.down_cursor})
            require(status in (200, 204), 'WEB carrier downlink failed')
            self.down_cursor = headers.get('X-Down-Cursor', self.down_cursor)
            if not body:
                continue
            for kind, stream, data in frames(body):
                if kind == 0x04 and stream == 1:
                    require(len(data) == 4, 'Invalid WEB stream window')
                    with self.credit_lock:
                        self.credit += struct.unpack('!I', data)[0]
                        self.credit_lock.notify_all()
                elif kind == 0x02 and stream == 1:
                    local.sendall(data)
                    self.uploads.put(frame(0x04, 1, struct.pack('!I', len(data))), timeout=5)
                elif kind == 0x05 and stream == 0:
                    self.uploads.put(frame(0x06, 0, data), timeout=5)
                elif kind in (0x03, 0x1f):
                    return
                else:
                    raise RuntimeError('Unexpected WEB carrier frame')

    def sender(self):
        while not self.stopped.is_set():
            try:
                body = self.uploads.get(timeout=.25)
            except queue.Empty:
                continue
            self.upload(body)

    def reader(self, local):
        # OPEN starts with implicit credit in both directions; waiting for a
        # first WINDOW would deadlock before the first backend payload.
        while not self.stopped.is_set():
            with self.credit_lock:
                require(self.credit_lock.wait_for(lambda: self.credit > 0, timeout=10),
                        'WEB backend did not replenish its stream window')
                allowance = min(65536, self.credit)
            data = local.recv(allowance)
            if not data:
                return
            with self.credit_lock:
                self.credit -= len(data)
            self.uploads.put(frame(0x02, 1, data), timeout=5)

    def bridge(self, local):
        def guarded(function):
            try:
                function()
            except (OSError, RuntimeError, ValueError, http.client.HTTPException, queue.Full) as error:
                self.failure.append(type(error).__name__)
            finally:
                self.stopped.set()
                try:
                    local.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        try:
            self.start()
            self.upload(frame(0x01, 1))
            workers = [threading.Thread(target=guarded, args=(function,), daemon=True)
                       for function in (self.sender, lambda: self.receive(local), lambda: self.reader(local))]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=40)
        except (OSError, RuntimeError, ValueError, http.client.HTTPException) as error:
            self.failure.append(type(error).__name__)
        finally:
            self.stopped.set()
            local.close()
            if self.token:
                try:
                    self.request('DELETE', 'api/v1/session', self.token)
                except (OSError, RuntimeError, http.client.HTTPException):
                    pass


def prove(settings, probe, dc):
    with socket.socket() as listener, tempfile.TemporaryDirectory(prefix='vpn-web-proof-') as temporary:
        listener.bind((env('VPN_LOOPBACK_IP'), 0))
        listener.listen(8)
        listener.settimeout(.25)
        stop = threading.Event()
        carriers = []

        def accept():
            while not stop.is_set():
                try:
                    local, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                carrier = Carrier(settings)
                carriers.append(carrier)
                threading.Thread(target=carrier.bridge, args=(local,), daemon=True).start()

        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        access = Path(temporary) / 'access.json'
        access.write_text(json.dumps({'server': env('VPN_LOOPBACK_IP'), 'port': listener.getsockname()[1],
                                      'secret': settings['secret']}))
        access.chmod(0o600)
        try:
            result = subprocess.run([str(probe), '--mode', 'mtproto', '--access', str(access), '--dc', str(dc)],
                                    capture_output=True, timeout=45)
            try:
                report = json.loads(result.stdout)
            except (ValueError, UnicodeDecodeError):
                raise RuntimeError('Native Telegram probe returned no structured proof') from None
            require(result.returncode == 0 and report.get('status') == 'passed'
                    and report.get('key_exchange') == 'passed' and report.get('rpc') == 'help.getNearestDC',
                    'Native Telegram DH or RPC failed through the WEB carrier')
            return {'web_carrier': 'https', 'native_library': report.get('library'), 'dc': dc,
                    'key_exchange': 'passed', 'rpc': report.get('rpc'), 'account_login': False,
                    'tls_verified': urlsplit(settings['origin']).scheme == 'https'}
        finally:
            stop.set()
            for carrier in carriers:
                carrier.stopped.set()
            worker.join(timeout=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--native-probe', type=Path, required=True)
    parser.add_argument('--dc', type=int, choices=range(1, 6), default=2)
    args = parser.parse_args()
    try:
        print(json.dumps(prove(read_private(args.settings), args.native_probe, args.dc)))
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'verify-web-proxy: ' + detail + '\n')


if __name__ == '__main__':
    main()
