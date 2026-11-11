#!/usr/bin/env python3
"""Install only the independent Grafana HTTPS proxy; preserve port 80 and VPN."""
import argparse
from contextlib import closing
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import time


NAME = 'vpn-grafana-https'
TIMER = NAME + '-certificate.timer'
UNIT = NAME + '-certificate.service'
ROOT = Path('/etc') / NAME
CONFIG = ROOT / 'nginx.conf'
INSTALLER = ROOT / 'install_grafana_https.py'
TLS_DIR = Path('/etc/vpn-failover-subscription')
TLS_BUNDLE = TLS_DIR / 'tls.pem'
UNIT_DIR = Path('/etc/systemd/system')
IMAGE = 'nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5'
LABEL = 'org.vpn-infra.grafana-https'


def command(*args, required=True):
    result = subprocess.run(args, capture_output=True, timeout=30)
    if required and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:2]))
    return result


def render(template, address):
    text = template.read_text()
    if '__GRAFANA_PUBLIC_IP__' not in text:
        raise ValueError('Missing public IP placeholder in nginx template')
    return text.replace('__GRAFANA_PUBLIC_IP__', str(ipaddress.IPv4Address(address)))


def source_fingerprint(address):
    for path in (TLS_DIR, TLS_BUNDLE):
        info = path.lstat()
        expected = stat.S_ISDIR if path == TLS_DIR else stat.S_ISREG
        if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o027:
            raise RuntimeError('Unsafe certificate directory or bundle')
    command('openssl', 'x509', '-in', str(TLS_BUNDLE), '-noout', '-checkend', '300')
    command('openssl', 'verify', '-purpose', 'sslserver', '-verify_ip', str(address),
            '-untrusted', str(TLS_BUNDLE), str(TLS_BUNDLE))
    der = command('openssl', 'x509', '-in', str(TLS_BUNDLE), '-outform', 'DER').stdout
    return hashlib.sha256(der).hexdigest()


def local_tls(address):
    raw = socket.create_connection(('127.0.0.1', 443), timeout=5)
    try:
        return ssl.create_default_context().wrap_socket(raw, server_hostname=str(address))
    except BaseException:
        raw.close()
        raise


def served_fingerprint(address):
    with local_tls(address) as tls:
        return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def get(address, path):
    # Connect to local nginx, but verify the exact public IP SAN and retain its Host.
    with closing(http.client.HTTPConnection(str(address), 443, timeout=5)) as connection:
        connection.sock = local_tls(address)
        connection.request('GET', path, headers={'Host': str(address), 'Connection': 'close'})
        response = connection.getresponse()
        return response.status, response.getheader('Location'), response.read(1024 * 1024)


def health(address, expected):
    if served_fingerprint(address) != expected:
        raise RuntimeError('New Grafana TLS certificate does not match the trusted source')
    status, location, _ = get(address, '/')
    if status != 302 or location != '/grafana/':
        raise RuntimeError('Grafana HTTPS root redirect failed')
    status, _, body = get(address, '/grafana/login')
    if status != 200 or f'https://{address}/grafana/'.encode() not in body or f'http://{address}/grafana/'.encode() in body:
        raise RuntimeError('Grafana login HTML does not use the HTTPS origin')
    status, _, body = get(address, '/grafana/api/health')
    if status != 200 or json.loads(body).get('database') != 'ok':
        raise RuntimeError('Grafana health API failed through HTTPS')


def inspect_container():
    result = command('docker', 'container', 'inspect', NAME, required=False)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def docker_options(network):
    return [f'--network={network}', '--pull=never', '--read-only', '--pids-limit=32',
            '--memory=96m', '--cpus=0.25', '--cap-drop=ALL', '--cap-add=NET_BIND_SERVICE',
            '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=CHOWN',
            '--security-opt=no-new-privileges:true', '--tmpfs=/tmp:rw,nodev,nosuid,noexec,mode=1777,size=32m',
            '--mount', f'type=bind,source={ROOT},target={ROOT},readonly',
            '--mount', f'type=bind,source={TLS_DIR},target={TLS_DIR},readonly',
            '--entrypoint=nginx']


def install(template, address):
    paths = (ROOT, UNIT_DIR / UNIT, UNIT_DIR / TIMER,
             UNIT_DIR / 'timers.target.wants' / TIMER)
    if any(os.path.lexists(path) for path in paths) or inspect_container() is not None:
        raise RuntimeError('An independent Grafana HTTPS installation already exists; not replacing it')
    for unit in (UNIT, TIMER):
        state = command('systemctl', 'show', '-p', 'LoadState', '--value', unit).stdout.strip()
        if state != b'not-found':
            raise RuntimeError('A Grafana HTTPS certificate unit already exists')
    with socket.socket() as check:
        check.bind(('0.0.0.0', 443))
    candidate = render(template, address)
    expected = source_fingerprint(address)
    own = secrets.token_hex(16)
    files = []
    mkdir = False
    try:
        ROOT.mkdir(mode=0o700)
        mkdir = True
        for path, data, mode in ((CONFIG, candidate.encode(), 0o640),
                                 (INSTALLER, Path(__file__).read_bytes(), 0o700)):
            with path.open('xb') as stream:
                files.append(path)
                stream.write(data)
            path.chmod(mode)
        command('docker', 'run', '--rm', *docker_options('none'), IMAGE, '-t', '-c', str(CONFIG))
        command('docker', 'run', '--detach', '--restart=unless-stopped', f'--name={NAME}',
                f'--label={LABEL}={own}', *docker_options('host'), IMAGE,
                '-c', str(CONFIG), '-g', 'daemon off;')
        for _ in range(20):
            try:
                health(address, expected)
                break
            except ConnectionRefusedError:
                time.sleep(.25)
        else:
            raise RuntimeError('Independent Grafana HTTPS listener did not become ready')
        cert_service = ('[Unit]\nDescription=Check the independent Grafana HTTPS certificate\n'
                        'After=docker.service\n[Service]\nType=oneshot\n'
                        f'ExecStart=/usr/bin/python3 -B {INSTALLER} sync --address {address}\n'
                        'NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\n'
                        'PrivateTmp=true\nRestrictAddressFamilies=AF_UNIX AF_INET\nUMask=0077\n')
        timer = ('[Unit]\nDescription=Watch the Grafana HTTPS certificate\n[Timer]\n'
                 f'OnBootSec=1min\nOnUnitActiveSec=5min\nAccuracySec=15s\nUnit={UNIT}\n'
                 '[Install]\nWantedBy=timers.target\n')
        for name, content in ((UNIT, cert_service), (TIMER, timer)):
            path = UNIT_DIR / name
            with path.open('x') as stream:
                files.append(path)
                stream.write(content)
            path.chmod(0o644)
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', TIMER)
    except BaseException:
        if UNIT_DIR / TIMER in files:
            command('systemctl', 'disable', '--now', TIMER, required=False)
        obj = inspect_container()
        if obj and obj.get('Config', {}).get('Labels', {}).get(LABEL) == own:
            command('docker', 'rm', '-f', obj['Id'], required=False)
        for path in reversed(files):
            path.unlink(missing_ok=True)
        if mkdir:
            ROOT.rmdir()
        if any(path.parent == UNIT_DIR for path in files):
            command('systemctl', 'daemon-reload', required=False)
        raise
    return {'grafana_https': 'installed', 'trusted_tls_and_login': True, 'port': 443}


def sync(address):
    obj = inspect_container()
    if obj is None or not obj.get('Config', {}).get('Labels', {}).get(LABEL):
        raise RuntimeError('Managed Grafana HTTPS container is missing')
    if not obj['State']['Running']:
        return {'grafana_https_certificate': 'not running; no action'}
    expected = source_fingerprint(address)
    try:
        current = served_fingerprint(address)
    except ssl.SSLCertVerificationError:
        current = None
    if current == expected:
        return {'grafana_https_certificate': 'current; no reload'}
    command('docker', 'exec', obj['Id'], 'nginx', '-t', '-c', str(CONFIG))
    command('docker', 'kill', '--signal=HUP', obj['Id'])
    for _ in range(40):
        try:
            if served_fingerprint(address) == expected:
                after = inspect_container()
                if after['Id'] != obj['Id'] or after['State']['Pid'] != obj['State']['Pid']:
                    raise RuntimeError('Unexpected Grafana HTTPS process change')
                return {'grafana_https_certificate': 'reloaded', 'pid_unchanged': True}
        except ssl.SSLCertVerificationError:
            pass
        time.sleep(.25)
    raise RuntimeError('Grafana HTTPS certificate reload was not observed')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('install', 'sync'):
        child = commands.add_parser(action)
        child.add_argument('--address', required=True, type=ipaddress.IPv4Address)
        if action == 'install':
            child.add_argument('template', type=Path)
    args = parser.parse_args()
    result = install(args.template, args.address) if args.action == 'install' else sync(args.address)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
