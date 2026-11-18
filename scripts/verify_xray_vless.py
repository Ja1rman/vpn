#!/usr/bin/env python3
"""Probe the existing native Xray VLESS entries with an isolated client core."""
import argparse
from contextlib import contextmanager
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from uuid import UUID

from compatible_profiles import x25519_public_key
from compatible_vless import enabled_clients
from verify_auto_onboarding import dns_probe


MAIN = Path('/usr/local/x-ui/bin/config.json')
DATABASE = Path('/etc/x-ui/x-ui.db')
XRAY = MAIN.with_name('xray-linux-amd64')
API = '127.0.0.1:62789'
REFLECTOR = 'https://api.ipify.org/'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_live_users(tag):
    result = subprocess.run([str(XRAY), 'api', 'inbounduser', '--server=' + API,
                             '--timeout=5', '--tag=' + tag], capture_output=True, timeout=7)
    require(result.returncode == 0, 'The main Xray user API failed')
    return {str(UUID(user['account']['id'])) for user in json.loads(result.stdout)['users']}


def outbound(config, port, address):
    candidates = [item for item in config['inbounds']
                  if item.get('port') == port and item.get('protocol') == 'vless']
    require(len(candidates) == 1, 'Expected one existing VLESS listener for the requested port')
    inbound = candidates[0]
    stream = inbound['streamSettings']
    require(stream.get('network') in ('raw', 'tcp'), 'This probe only supports native TCP VLESS')
    security = stream.get('security', 'none')
    require(security in ('none', 'reality', 'tls'), 'Unsupported VLESS TLS transport')
    require(security != 'none' or ipaddress.ip_address(address).is_private,
            'This Xray prohibits unencrypted VLESS to a public IP; use loopback to test its server authorization')
    allowed = enabled_clients(DATABASE, port)
    live = read_live_users(inbound['tag'])
    users = [user for user in inbound['settings']['clients']
             if str(UUID(user['id'])) in live and str(UUID(user['id'])) in allowed]
    require(users, 'No enabled live user is available on this VLESS listener')
    user = users[0]
    uid = str(UUID(user['id']))
    require(user.get('flow', '') == allowed[uid], 'The saved and authorized VLESS flow differ')
    transport = {'network': stream['network'], 'security': security}
    for key in ('tcpSettings', 'rawSettings'):
        if key in stream:
            transport[key] = copy.deepcopy(stream[key])
    if security == 'reality':
        reality = stream['realitySettings']
        names = reality.get('serverNames', [])
        ids = reality.get('shortIds', [])
        require(names and ids, 'The existing REALITY listener has no SNI or short ID')
        transport['realitySettings'] = {
            'serverName': 'yandex.ru' if 'yandex.ru' in names else names[0],
            'fingerprint': 'chrome', 'publicKey': x25519_public_key(reality['privateKey']),
            'shortId': ids[0], 'spiderX': '/',
        }
    if security == 'tls':
        name = stream.get('tlsSettings', {}).get('serverName')
        require(name, 'A trusted TLS name is required for this existing listener')
        transport['tlsSettings'] = {'serverName': name, 'allowInsecure': False}
    settings = {'address': address, 'port': port, 'id': uid,
                'encryption': 'none', 'flow': allowed[uid]}
    return {'protocol': 'vless', 'tag': 'existing-entry', 'settings': settings,
            'streamSettings': transport}


@contextmanager
def isolated_client(remote):
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    account = (secrets.token_hex(12), secrets.token_hex(24))
    config = {
        'log': {'loglevel': 'none', 'access': 'none'},
        'inbounds': [{'tag': 'probe', 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                      'settings': {'auth': 'password', 'udp': True,
                                   'accounts': [{'user': account[0], 'pass': account[1]}]}}],
        'outbounds': [remote],
    }
    with tempfile.TemporaryDirectory(prefix='vpn-xray-vless-') as folder:
        path = Path(folder) / 'client.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([str(XRAY), 'run', '-config', str(path)],
                                   env=dict(os.environ, XRAY_LOCATION_ASSET=str(XRAY.parent)),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(30):
                require(process.poll() is None, 'The isolated Xray client failed to start')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('The isolated SOCKS listener did not start')
            yield port, account
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def reflect_ipv4(port, account):
    private = 'proxy-user = ' + json.dumps(':'.join(account)) + '\n'
    result = subprocess.run(
        ['curl', '-q', '--silent', '--fail', '--ipv4', '--noproxy', '', '--proto', '=https',
         '--connect-timeout', '4', '--max-time', '8', '--max-filesize', '128',
         '--proxy', f'socks5h://127.0.0.1:{port}', '--config', '-', REFLECTOR],
        input=private.encode(), capture_output=True, timeout=10)
    require(result.returncode == 0, 'The native VLESS HTTPS probe failed (curl ' + str(result.returncode) + ')')
    address = ipaddress.IPv4Address(result.stdout.decode('ascii').strip())
    require(address.is_global, 'The HTTPS reflector did not return a public IPv4')
    return str(address)


def probe(config, port, address, expected):
    result = {'port': port, 'transport': 'native-xray', 'tcp_https': 'failed', 'udp_dns': 'failed'}
    try:
        candidate = outbound(config, port, address)
        result['security'] = candidate['streamSettings']['security']
        with isolated_client(candidate) as (local, account):
            try:
                egress = reflect_ipv4(local, account)
                require(expected is None or egress == expected, 'The VLESS egress differs from the expected IPv4')
                result.update(tcp_https='passed', exit_ipv4=egress)
            except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
                result['tcp_error'] = str(exc) if type(exc) is RuntimeError else type(exc).__name__
            try:
                dns_probe(local, account)
                result['udp_dns'] = 'passed'
            except (RuntimeError, OSError) as exc:
                result['udp_error'] = str(exc) if type(exc) is RuntimeError else type(exc).__name__
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result['setup_error'] = str(exc) if type(exc) is RuntimeError else type(exc).__name__
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ports', type=int, nargs='+', default=[33172, 46738])
    parser.add_argument('--dial-address', default='127.0.0.1', choices=['127.0.0.1', '212.22.70.156'])
    parser.add_argument('--expected-ip', type=ipaddress.IPv4Address)
    args = parser.parse_args()
    try:
        require(all(0 < port < 65536 for port in args.ports), 'Invalid requested VLESS port')
        raw = MAIN.read_bytes()
        before = hashlib.sha256(raw).digest()
        config = json.loads(raw)
        reports = [probe(config, port, args.dial_address,
                         str(args.expected_ip) if args.expected_ip else None) for port in dict.fromkeys(args.ports)]
        require(hashlib.sha256(MAIN.read_bytes()).digest() == before,
                'The main Xray config changed during the probe; rerun against current state')
        print(json.dumps({'checks': reports, 'main_config_unchanged': True}))
        if any(row['tcp_https'] != 'passed' or row['udp_dns'] != 'passed' for row in reports):
            raise SystemExit(1)
    except (OSError, RuntimeError, ValueError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'verify-xray-vless: ' + detail + '\n')


if __name__ == '__main__':
    main()
