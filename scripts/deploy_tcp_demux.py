#!/usr/bin/env python3
"""Deploy a scoped ingress classifier; keep verification and commit explicit."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile

import vpnctl
from vpn_env import env, port


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/tcp-demux'
HELPER = '/etc/vpn-tcp-demux/install_tcp_demux.py'


def configuration(host):
    entry = host == 'entry'
    role = 'ENTRY' if entry else 'NL'
    address, interface = env('VPN_' + role + '_INGRESS_IP'), env('VPN_' + role + '_INGRESS_INTERFACE')
    public = port('VPN_MONITORING_HTTPS_PORT' if entry else 'VPN_NL_TELEGRAM_PUBLIC_PORT')
    listen, loopback = port('VPN_' + role + '_TELEGRAM_MUX_PORT'), env('VPN_LOOPBACK_IP')
    return {'address': address, 'interface': interface, 'public_port': public, 'listen_port': listen,
            'classifier': {'listen': f'{address}:{listen}', 'redirected_from': f'{address}:{public}',
                           'default_target': f'{loopback}:{public}',
                           'tls_sni_targets': {'yandex.ru': f'{loopback}:' + str(port(
                               'VPN_MTPROTO_PORT' if entry else 'VPN_NL_MTPROTO_EE_PORT'))},
                           'socks_target': f'{loopback}:' + str(port(
                               'VPN_TELEGRAM_SOCKS_PORT' if entry else 'VPN_NL_TELEGRAM_SOCKS_PORT')),
                           'raw_target': f'{loopback}:' + str(port(
                               'VPN_MTPROTO_DD_PORT' if entry else 'VPN_NL_MTPROTO_DD_PORT'))}}


def build():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = ROOT / 'tools/tcp-demux'
    fingerprint = hashlib.sha256(b''.join(path.name.encode() + b'\0' + path.read_bytes()
        for path in sorted(source.iterdir()) if path.suffix == '.go' or path.name == 'go.mod')).hexdigest()
    binary, manifest = PRIVATE / 'tcp-demux-linux-amd64', PRIVATE / 'build.json'
    if binary.is_file() and manifest.is_file():
        known = json.loads(manifest.read_text())
        if known.get('source_sha256') == fingerprint and hashlib.sha256(binary.read_bytes()).hexdigest() == known.get('binary_sha256'):
            return binary, known['binary_sha256']
    environment = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOMAXPROCS='2',
                       GOCACHE=str(PRIVATE / 'build-cache'))
    result = subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(binary), '.'],
                            cwd=source, env=environment, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError('Ingress classifier build failed')
    checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({'source_sha256': fingerprint, 'binary_sha256': checksum}, indent=2) + '\n')
    manifest.chmod(0o600)
    return binary, checksum


def deploy(host):
    binary, checksum = build()
    settings = configuration(host)
    private = PRIVATE / host
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings_file = private / 'settings.json'
    settings_file.write_text(json.dumps(settings, indent=2) + '\n')
    settings_file.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='tcp-demux-', dir=ROOT / '.local') as temporary:
        folder = Path(temporary)
        shutil.copyfile(binary, folder / 'tcp-demux')
        shutil.copyfile(settings_file, folder / 'settings.json')
        (folder / 'settings.json').chmod(0o600)
        stage = vpnctl.upload(host, folder, ['install_tcp_demux.py'])
        try:
            result = vpnctl.remote(host, 'sudo python3 -B ' + shlex.join([
                stage + '/install_tcp_demux.py', 'install', '--binary', stage + '/payload/tcp-demux',
                '--sha256', checksum, '--settings', stage + '/payload/settings.json']), capture=True)
            return json.loads(result.stdout)
        finally:
            vpnctl.remote(host, 'sudo rm -rf -- ' + shlex.quote(stage))


def action(host, name, proof=None, transaction=None):
    if name == 'install':
        return deploy(host)
    arguments = ['sudo', 'python3', '-B', HELPER, name]
    if transaction:
        arguments.extend(['--transaction', transaction])
    if name != 'commit':
        return json.loads(vpnctl.remote(host, shlex.join(arguments), capture=True).stdout)
    if proof is None:
        raise ValueError('Commit requires a private external verification report')
    with tempfile.TemporaryDirectory(prefix='ingress-proof-', dir=ROOT / '.local') as temporary:
        folder = Path(temporary)
        shutil.copyfile(proof, folder / 'proof.json')
        (folder / 'proof.json').chmod(0o600)
        stage = vpnctl.upload(host, folder)
        try:
            arguments.extend(['--proof-file', stage + '/payload/proof.json'])
            return json.loads(vpnctl.remote(host, shlex.join(arguments), capture=True).stdout)
        finally:
            vpnctl.remote(host, 'sudo rm -rf -- ' + shlex.quote(stage))


def backend_native_socks(host):
    import verify_telegram_backend as backend
    import verify_telegram_ingress as verifier

    role = 'entry' if host == 'entry' else 'nl'
    _, _, inputs = verifier.host_settings(role)
    credentials = json.loads(inputs['socks'].read_text())
    expected = backend.authentication_digest(credentials['username'], credentials['password'])
    binary = ROOT / '.local/telegram-probe/telegram-probe-linux-amd64'
    if not binary.is_file():
        raise RuntimeError('Build the pinned Linux Telegram probe before HTTPS-only SOCKS verification')
    with tempfile.TemporaryDirectory(prefix='telegram-backend-', dir=ROOT / '.local') as temporary:
        folder = Path(temporary)
        shutil.copyfile(binary, folder / 'telegram-probe')
        (folder / 'telegram-probe').chmod(0o700)
        # Only the public probe and endpoint registry are uploaded. The helper
        # reads credentials already present on that same host into a local tmp.
        stage = vpnctl.upload(host, folder, ['verify_telegram_backend.py'])
        try:
            response = vpnctl.remote(host, 'sudo python3 -B ' + shlex.join([
                stage + '/verify_telegram_backend.py', '--role', role,
                '--credentials-digest', expected, '--probe', stage + '/payload/telegram-probe']), capture=True)
            result = json.loads(response.stdout)
            if not result.get('native_socks_backend') or not result.get('credentials_match_public_client'):
                raise RuntimeError('The live SOCKS Telegram backend did not pass')
            return result
        finally:
            vpnctl.remote(host, 'sudo rm -rf -- ' + shlex.quote(stage))


def activate(host, interface=None, socks_proof='telegram'):
    """Arm, prove actual public clients, then commit or detach our exact rule."""
    import verify_telegram_ingress as verifier

    if socks_proof not in ('telegram', 'https'):
        raise ValueError('Choose an explicit SOCKS verification mode')
    backend = backend_native_socks(host) if socks_proof == 'https' else None
    role = 'entry' if host == 'entry' else 'nl'
    address, number, _ = verifier.host_settings(role)
    server_name = address if role == 'entry' else 'github.com'
    raw = socket.create_connection((address, number), timeout=10)
    secured = ssl.create_default_context().wrap_socket(raw, server_hostname=server_name)
    connection = http.client.HTTPConnection(address, number, timeout=10)
    connection.sock = secured

    def request():
        connection.request('GET' if role == 'entry' else 'HEAD',
                           '/grafana/api/health' if role == 'entry' else '/',
                           headers={'Host': server_name, 'Connection': 'keep-alive'})
        response = connection.getresponse()
        body = response.read(1024 * 1024)
        return (response.status == 200 and json.loads(body).get('database') == 'ok'
                if role == 'entry' else response.status in (200, 301, 302, 307, 308))

    armed = None
    try:
        if not request():
            raise RuntimeError('Original public TLS preflight failed')
        held = connection.sock is secured
        armed = action(host, 'apply')
        if armed.get('already_committed'):
            return armed
        if not armed.get('armed') or not armed.get('transaction'):
            raise RuntimeError('Ingress watchdog was not armed')
        same_connection = request() and connection.sock is secured if held else None
        if held and not same_connection:
            raise RuntimeError('The pre-existing original TLS socket failed')
        report_path = PRIVATE / host / 'public-proof.json'
        report = verifier.verify(role, report_path, interface=interface)
        socks_passed = (report['native_socks'] if socks_proof == 'telegram' else
                        report.get('socks_https', {}).get('passed') is True
                        and backend['native_socks_backend'] is True)
        proof = {'original_tls': report['default_tls']['trusted_tls']
                 and report['default_tls']['original_http_service_healthy'],
                 'new_protocols': report['native_ee'] and report['native_dd'] and socks_passed,
                 'held_original_tls_preserved': same_connection,
                 'host_role': role, 'transaction': armed['transaction'], 'native_report': report,
                 'socks_proof_mode': socks_proof, 'socks_backend': backend}
        destination = report_path.with_name('commit-proof.json')
        destination.write_text(json.dumps(proof, indent=2) + '\n')
        destination.chmod(0o600)
        if not proof['original_tls'] or not proof['new_protocols']:
            raise RuntimeError('Public native Telegram/TLS verification failed; see private report')
        result = action(host, 'commit', proof=destination)
        return result | {'held_original_tls_preserved': same_connection,
                         'native_ee': report['native_ee'], 'native_dd': report['native_dd'],
                         'native_socks': report['native_socks'], 'socks_proof_mode': socks_proof,
                         'socks_https': report.get('socks_https'),
                         'vpn_off_verified': False}
    except BaseException:
        if armed and armed.get('transaction'):
            action(host, 'rollback', transaction=armed['transaction'])
        raise
    finally:
        connection.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'activate', 'apply', 'commit', 'rollback'])
    parser.add_argument('--host', choices=['entry', 'breeze-reef'], required=True)
    parser.add_argument('--proof', type=Path)
    parser.add_argument('--transaction')
    parser.add_argument('--interface', default=os.environ.get('VPN_TELEGRAM_PROBE_INTERFACE'))
    parser.add_argument('--socks-proof', choices=['telegram', 'https'], default='telegram',
                        help='HTTPS mode publishes SOCKS with its public Telegram limitation recorded')
    args = parser.parse_args()
    result = (activate(args.host, args.interface, args.socks_proof) if args.action == 'activate'
              else action(args.host, args.action, args.proof, args.transaction))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
