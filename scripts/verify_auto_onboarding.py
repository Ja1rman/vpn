#!/usr/bin/env python3
"""Verify a derived VPN Auto TLS profile without editing x-ui or its users."""
import argparse
import base64
from contextlib import closing, contextmanager, ExitStack
import http.client
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from failover_subscription import (InvalidSubscription, LoopbackHTTPSConnection, MAX_BODY,
                                   MissingSubscription, Settings, SUB_PATH, rewrite_profile)


DATABASE = Path('/etc/x-ui/x-ui.db')
SING_BOX = '/opt/vpn-compatible-vless/sing-box'
LOOPBACK = '127.0.0.1'
POOL_PORT = 11092
REFLECTOR = 'https://api.ipify.org/'


class ProbeError(RuntimeError):
    """The message is safe to report without subscription or client data."""


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def account_rows(settings):
    uri = DATABASE.resolve(strict=True).as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
        return connection.execute('''
            SELECT c.sub_id, c.uuid FROM clients AS c
            JOIN client_inbounds AS ci ON ci.client_id = c.id
            JOIN inbounds AS i ON i.id = ci.inbound_id
            WHERE i.port = ? AND i.protocol = 'vless' AND i.enable = 1 AND c.enable = 1
              AND c.sub_id != '' AND (c.expiry_time <= 0 OR c.expiry_time > ?)
            ORDER BY c.id LIMIT 32
        ''', (settings.tls_source_port, int(time.time() * 1000))).fetchall()


def source_lines(sub_id, settings, trust):
    path = '/sub/' + sub_id
    require(SUB_PATH.fullmatch(path), 'Unexpected x-ui subscription ID format')
    with closing(LoopbackHTTPSConnection(settings.address, settings.upstream_port, context=trust, timeout=5)) as client:
        client.request('GET', path, headers={'Accept': 'text/plain', 'Accept-Encoding': 'identity'})
        response = client.getresponse()
        if response.status in (400, 401, 403, 404, 410):
            return []
        require(response.status == 200 and response.getheader('Content-Encoding', 'identity').lower() == 'identity',
                'The x-ui feed returned an unexpected response')
        data = response.read(MAX_BODY + 1)
    require(len(data) <= MAX_BODY, 'The x-ui feed is larger than expected')
    if b'://' not in data:
        data = b''.join(data.split())
        data = base64.b64decode(data + b'=' * (-len(data) % 4), validate=True)
    return data.decode('utf-8-sig').splitlines()


def derived_profile(settings):
    trust = ssl.create_default_context()
    for sub_id, expected_uid in account_rows(settings):
        candidates = []
        for line in source_lines(sub_id, settings, trust):
            if line.startswith('vless://'):
                link = urlsplit(line)
                if link.hostname == settings.address and link.port == settings.tls_source_port:
                    candidates.append(line)
        if not candidates:
            continue
        require(len(candidates) == 1, 'The x-ui feed returned ambiguous VLESS sources')
        # Emulate an account that only has the ordinary x-ui VLESS profile.
        encoded = rewrite_profile(candidates[0].encode(), settings)
        link = urlsplit(base64.b64decode(encoded, validate=True).decode().strip())
        options = parse_qs(link.query, keep_blank_values=True)
        require(link.scheme == 'vless' and link.hostname == settings.address and link.port == settings.tls_target_port
                and link.username == str(UUID(expected_uid)) and link.password is None and not link.path
                and options == {'type': ['tcp'], 'security': ['tls'], 'encryption': ['none'],
                                'packetEncoding': ['xudp']},
                'The derived TLS profile did not match its x-ui account and expected transport')
        return link
    raise ProbeError('No eligible VLESS profile was available in the x-ui feed')


def local_ports():
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(2)]
        for handle in sockets:
            handle.bind((LOOPBACK, 0))
        return [handle.getsockname()[1] for handle in sockets]


@contextmanager
def temporary_client(profile, dial_address, account):
    ports = local_ports()
    username, password = account
    config = {'log': {'disabled': True}, 'inbounds': [], 'outbounds': [], 'route': {'rules': []}}
    for tag, port, uid in zip(('valid', 'unknown'), ports, (profile.username, str(uuid4()))):
        config['inbounds'].append({'type': 'socks', 'tag': tag, 'listen': LOOPBACK, 'listen_port': port,
                                   'users': [{'username': username, 'password': password}]})
        config['outbounds'].append({'type': 'vless', 'tag': tag, 'server': dial_address,
                                    'server_port': profile.port, 'uuid': uid, 'packet_encoding': 'xudp',
                                    'tls': {'enabled': True, 'server_name': profile.hostname}})
        config['route']['rules'].append({'inbound': [tag], 'action': 'route', 'outbound': tag})
    with tempfile.TemporaryDirectory(prefix='vpn-auto-onboarding-') as directory:
        path = Path(directory) / 'client.json'
        path.write_text(json.dumps(config))
        proc = subprocess.Popen([SING_BOX, 'run', '-c', str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for port in ports:
                for _ in range(30):
                    require(proc.poll() is None, 'The isolated sing-box client failed to start')
                    try:
                        with socket.create_connection((LOOPBACK, port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise ProbeError('The isolated SOCKS listener did not start')
            yield ports
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def reflect(port, account=None):
    proxy_config = ''
    if account:
        proxy_config = 'proxy-user = ' + json.dumps(':'.join(account)) + '\n'
    return subprocess.run(
        ['curl', '-q', '--silent', '--fail', '--ipv4', '--noproxy', '', '--proto', '=https',
         '--connect-timeout', '5', '--max-time', '10', '--max-filesize', '128',
         '--proxy', f'socks5h://{LOOPBACK}:{port}', '--config', '-', REFLECTOR],
        input=proxy_config.encode(), capture_output=True, timeout=12,
    )


def reflect_ipv4(port, account=None):
    result = reflect(port, account)
    require(result.returncode == 0, 'The HTTPS egress probe failed')
    address = IPv4Address(result.stdout.decode('ascii').strip())
    require(address.is_global, 'The HTTPS probe did not return a public IPv4 address')
    return address


def dns_probe(port, account):
    username, password = (value.encode() for value in account)
    with socket.create_connection((LOOPBACK, port), timeout=5) as control, control.makefile('rb') as stream:
        control.sendall(b'\x05\x01\x02')
        require(stream.read(2) == b'\x05\x02', 'The SOCKS UDP greeting failed')
        control.sendall(bytes((1, len(username))) + username + bytes((len(password),)) + password)
        require(stream.read(2) == b'\x01\x00', 'The SOCKS UDP authentication failed')
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        require(stream.read(4) == b'\x05\x00\x00\x01', 'The SOCKS UDP relay did not start')
        address, relay_port = stream.read(4), int.from_bytes(stream.read(2), 'big')
        require(address in (b'\0' * 4, socket.inet_aton(LOOPBACK)) and relay_port, 'Unexpected SOCKS UDP relay')
        query_id = secrets.token_bytes(2)
        header = b'\0\0\0\x01\x01\x01\x01\x01\x00\x35'
        query = query_id + b'\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.connect((LOOPBACK, relay_port))
            udp.send(header + query)
            response = udp.recv(4096)
        require(len(response) >= 22 and response.startswith(header + query_id)
                and bool(response[12] & 128) and response[13] & 15 == 0,
                'The XUDP probe did not receive a valid DNS reply')


def main():
    os.umask(0o077)
    settings = Settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dial-address', choices=(LOOPBACK, settings.address), default=LOOPBACK,
                        help='Connect locally or test the public gateway address from this host')
    args = parser.parse_args()
    try:
        profile = derived_profile(settings)
        expected = reflect_ipv4(POOL_PORT)
        require(expected != IPv4Address(settings.address), 'The Auto pool probe did not use a foreign egress')
        account = (secrets.token_hex(12), secrets.token_hex(24))
        with temporary_client(profile, args.dial_address, account) as (valid, unknown):
            require(reflect_ipv4(valid, account) == expected, 'TLS VPN and the Auto pool use different egresses')
            dns_probe(valid, account)
            rejected = reflect(unknown, account)
            require(rejected.returncode in (35, 52, 55, 56, 97) and not rejected.stdout,
                    'The unknown VLESS UUID was not conclusively rejected')
            require(reflect_ipv4(valid, account) == expected,
                    'The valid VPN connection failed after the rejection check')
        print(json.dumps({'derived_tls': 'passed', 'trusted_ip_san': 'passed', 'auto_egress': str(expected),
                          'xudp_dns': 'passed', 'unknown_uuid': 'rejected'}))
    except (OSError, TypeError, ValueError, RuntimeError, InvalidSubscription, MissingSubscription,
            http.client.HTTPException, sqlite3.Error, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        parser.exit(1, 'verify-auto-onboarding: ' + detail + '\n')


if __name__ == '__main__':
    main()
