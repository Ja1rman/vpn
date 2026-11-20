#!/usr/bin/env python3
"""Anonymous native-client proof of a public Telegram ingress; never changes client routing."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tempfile

from vpn_env import env, port


ROOT = Path(__file__).resolve().parents[1]
ROLES = ('ee', 'dd', 'socks')


def host_settings(host):
    if host == 'entry':
        return (env('VPN_ENTRY_ADDRESS'), port('VPN_MONITORING_HTTPS_PORT'),
                {'ee': ROOT / '.local/mtproto/access.json',
                 'dd': ROOT / '.local/mtproto-dd/access.json',
                 'socks': ROOT / '.local/telegram-socks/access.json'})
    if host == 'nl':
        return (env('VPN_NL_ADDRESS'), port('VPN_NL_TELEGRAM_PUBLIC_PORT'),
                {role: ROOT / '.local/telegram-reserve/nl' / role / 'access.json' for role in ROLES})
    raise RuntimeError('Choose an explicitly configured ingress host')


def access_for_ingress(path, role, address, ingress_port):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
        raise RuntimeError('A proxy access input must be a private regular JSON file')
    value = json.loads(path.read_text())
    keys = ('username', 'password') if role == 'socks' else ('secret',)
    if not isinstance(value, dict) or not all(isinstance(value.get(key), str) and value[key] for key in keys):
        raise RuntimeError('A private proxy input is missing authentication fields')
    return {'server': address, 'port': ingress_port, **{key: value[key] for key in keys}}


def private_write(path, document):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(document, stream, indent=2)
        stream.write('\n')


def native_check(probe, role, access_path, *, dc=2, interface=None):
    arguments = [str(probe), '--mode', 'socks' if role == 'socks' else 'mtproto',
                 '--access', str(access_path), '--dc', str(dc)]
    if interface:
        arguments += ['--interface', interface]
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=43)
        row = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {'passed': False, 'error_class': 'timeout'}
    except (OSError, ValueError):
        return {'passed': False, 'error_class': 'client_execution_or_output'}
    success = (result.returncode == 0 and row.get('status') == 'passed'
               and row.get('account_login') is False and row.get('key_exchange') == 'passed'
               and row.get('rpc') == 'help.getNearestDC' and row.get('this_dc') == dc)
    output = {'passed': success, 'key_exchange_and_anonymous_rpc': success}
    if not success:
        allowed = {'timeout', 'deadline', 'refused', 'authentication', 'handshake', 'fingerprint',
                   'rpc', 'client_failure'}
        output['error_class'] = row.get('error_class') if row.get('error_class') in allowed else 'client_failure'
    elif isinstance(row.get('elapsed_ms'), int):
        output['elapsed_ms'] = row['elapsed_ms']
    return output


class SocksProbeFailure(RuntimeError):
    """A fixed diagnostic category, never a remote peer's text."""


def receive_exact(connection, length):
    body = bytearray()
    while len(body) < length:
        chunk = connection.recv(length - len(body))
        if not chunk:
            raise SocksProbeFailure('connection_closed')
        body.extend(chunk)
    return bytes(body)


def socks_https_check(access_path, *, interface=None):
    """Use a raw TCP socket: no process-wide HTTP/SOCKS proxy configuration is consulted."""
    report = {name: False for name in ('passed', 'tcp_connected', 'auth_method_accepted',
              'credentials_accepted', 'connect_request_sent', 'connect_reply_received',
              'target_connect_accepted', 'trusted_tls', 'https_response_received')}
    raw = secured = None
    try:
        info = access_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
            raise SocksProbeFailure('unsafe_private_input')
        value = json.loads(access_path.read_text())
        username, password = value['username'].encode(), value['password'].encode()
        if not 1 <= len(username) <= 255 or not 1 <= len(password) <= 255:
            raise SocksProbeFailure('invalid_authentication_input')
        target = 'docs.python.org'
        encoded = target.encode('idna')
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(12)
        if interface:
            if sys.platform == 'darwin':
                # IP_BOUND_IF is a socket option; it does not establish bypass of Network Extensions.
                raw.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
            elif sys.platform.startswith('linux'):
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\x00')
            else:
                raise SocksProbeFailure('interface_scoping_unsupported')
        raw.connect((value['server'], value['port']))
        report['tcp_connected'] = True
        raw.sendall(b'\x05\x01\x02')
        if receive_exact(raw, 2) != b'\x05\x02':
            raise SocksProbeFailure('auth_method_rejected')
        report['auth_method_accepted'] = True
        raw.sendall(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
        if receive_exact(raw, 2) != b'\x01\x00':
            raise SocksProbeFailure('authentication_rejected')
        report['credentials_accepted'] = True
        raw.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded
                    + port('VPN_TELEGRAM_VERIFY_HTTPS_PORT').to_bytes(2, 'big'))
        report['connect_request_sent'] = True
        reply = receive_exact(raw, 4)
        report['connect_reply_received'] = True
        if reply[0] != 5 or reply[2] != 0:
            raise SocksProbeFailure('invalid_connect_reply')
        if reply[1] != 0:
            raise SocksProbeFailure('proxy_connect_rejected')
        if reply[3] == 1:
            receive_exact(raw, 4 + 2)
        elif reply[3] == 3:
            receive_exact(raw, receive_exact(raw, 1)[0] + 2)
        elif reply[3] == 4:
            receive_exact(raw, 16 + 2)
        else:
            raise SocksProbeFailure('invalid_connect_reply')
        report['target_connect_accepted'] = True
        secured = ssl.create_default_context().wrap_socket(raw, server_hostname=target)
        report['trusted_tls'] = True
        secured.sendall(b'HEAD /3/ HTTP/1.1\r\nHost: docs.python.org\r\nConnection: close\r\n\r\n')
        response = http.client.HTTPResponse(secured)
        response.begin()
        report['https_response_received'] = True
        report['http_status'] = response.status
        report['passed'] = 200 <= response.status < 400
        if not report['passed']:
            report['error_class'] = 'http_status'
    except SocksProbeFailure as error:
        report['error_class'] = str(error)
    except ssl.SSLCertVerificationError:
        report['error_class'] = 'certificate_verification'
    except ssl.SSLError:
        report['error_class'] = 'tls_handshake'
    except (socket.timeout, TimeoutError):
        report['error_class'] = 'timeout'
    except ConnectionRefusedError:
        report['error_class'] = 'connection_refused'
    except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException):
        report['error_class'] = 'socket_or_private_input'
    finally:
        if secured is not None:
            secured.close()
        elif raw is not None:
            raw.close()
    return report


def default_tls_check(host, address, ingress_port):
    context = ssl.create_default_context()
    try:
        if host == 'entry':
            connection = http.client.HTTPSConnection(address, ingress_port, context=context, timeout=12)
            try:
                connection.request('GET', '/grafana/api/health')
                response = connection.getresponse()
                body = response.read(16384)
                healthy = response.status == 200 and json.loads(body).get('database') == 'ok'
                return {'trusted_tls': True, 'original_http_service_healthy': healthy,
                        'full_vpn_authentication_tested': False}
            finally:
                connection.close()
        with socket.create_connection((address, ingress_port), timeout=12) as raw:
            with context.wrap_socket(raw, server_hostname='github.com') as secured:
                secured.sendall(b'HEAD / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n')
                response = http.client.HTTPResponse(secured)
                response.begin()
                return {'trusted_tls': True, 'original_http_service_healthy': response.status in (200, 301, 302, 307, 308),
                        'full_vpn_authentication_tested': False}
    except (OSError, ValueError, http.client.HTTPException):
        return {'trusted_tls': False, 'original_http_service_healthy': False,
                'full_vpn_authentication_tested': False}


def verify(host, result_path, *, gotd=None, interface=None, dc=2):
    if not 1 <= dc <= 5:
        raise RuntimeError('Invalid Telegram data center')
    address, ingress_port, inputs = host_settings(host)
    gotd = Path(gotd or ROOT / '.local/telegram-probe/telegram-probe')
    if not gotd.is_file() or not os.access(gotd, os.X_OK):
        raise RuntimeError('Build the pinned public Telegram client probe locally first')
    private = ROOT / '.local'
    private.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='telegram-public-ingress-', dir=private) as temporary:
        folder = Path(temporary)
        paths = {}
        for role in ROLES:
            paths[role] = folder / (role + '.json')
            private_write(paths[role], access_for_ingress(inputs[role], role, address, ingress_port))
        with ThreadPoolExecutor(max_workers=len(ROLES) + 1) as executor:
            pending = {role: executor.submit(native_check, gotd, role, paths[role], dc=dc,
                                              interface=interface) for role in ROLES}
            ordinary_https = executor.submit(socks_https_check, paths['socks'], interface=interface)
            tls = default_tls_check(host, address, ingress_port)
            proofs = {role: task.result() for role, task in pending.items()}
            socks_https = ordinary_https.result()
    report = {'host_role': host, 'native_ee': proofs['ee']['passed'], 'native_dd': proofs['dd']['passed'],
              'native_socks': proofs['socks']['passed'], 'native_clients': proofs,
              'socks_https': socks_https,
              'default_tls': tls, 'temporary_access_files_removed': True, 'account_login': False,
              'network_context': 'public-client-path-with-existing-network-policy',
              'vpn_off_verified': False, 'interface_scoped': bool(interface)}
    destination = Path(result_path)
    if destination.exists():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RuntimeError('Refusing to replace an unsafe result file')
        destination.unlink()
    private_write(destination, report)
    return report


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=('entry', 'nl'), required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--gotd', type=Path)
    parser.add_argument('--interface')
    parser.add_argument('--dc', type=int, default=2)
    args = parser.parse_args()
    try:
        report = verify(args.host, args.result, gotd=args.gotd, interface=args.interface, dc=args.dc)
    except (RuntimeError, OSError, ValueError):
        raise SystemExit('Public ingress verification refused or failed; no secret values were logged') from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if all(report[key] for key in ('native_ee', 'native_dd', 'native_socks'))
                     and report['default_tls']['trusted_tls']
                     and report['default_tls']['original_http_service_healthy'] else 1)


if __name__ == '__main__':
    main()
