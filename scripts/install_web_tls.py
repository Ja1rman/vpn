#!/usr/bin/env python3
"""Co-host Telegram WEB on existing nginx with isolated ACME and graceful reloads."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

import install_web_proxy as relay
import install_grafana_https as grafana
from vpn_env import configured_values, env, port

ROOT = Path('/etc/vpn-telegram-web-tls')
ACME = ROOT / 'acme'
HTTP_CONFIG = Path('/etc/vpn-monitoring/nginx.conf')
HTTPS_CONFIG = Path('/etc/vpn-grafana-https/nginx.conf')
BUNDLE = HTTPS_CONFIG.parent / 'telegram-web.pem'
HTTP_CONTAINER = 'vpn-monitoring-web-1'
HTTPS_CONTAINER = 'vpn-grafana-https'
UNIT = 'vpn-telegram-web-certificate'
BEGIN = '  # BEGIN vpn-telegram-web managed server\n'
END = '  # END vpn-telegram-web managed server\n'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'WEB TLS command failed: ' + args[0])
    return result.stdout


def insert_server(source, server):
    """Append one owned HTTP server; never rewrite other servers or routes."""
    require(source.rstrip().endswith('}'), 'Unexpected nginx configuration ending')
    if BEGIN in source or END in source:
        require(source.count(BEGIN) == source.count(END) == 1, 'Ambiguous WEB TLS marker')
        before, rest = source.split(BEGIN)
        old, after = rest.split(END)
        require(old == server, 'Existing WEB TLS configuration differs; refusing to replace it')
        return source
    head, closing = source.rstrip().rsplit('}', 1)
    require(not closing, 'Unexpected nginx configuration ending')
    return head + BEGIN + server + END + '}\n'


def challenge_server(settings):
    return f'''  server {{
    listen {env('VPN_BIND_IP')}:{port('VPN_MONITORING_HTTP_PORT')};
    server_name {settings.hostname};
    access_log off;
    location ^~ /.well-known/acme-challenge/ {{
      proxy_pass http://{settings.loopback}:{port('VPN_WEB_ACME_PORT')};
      proxy_set_header Host $host;
      proxy_buffering off;
    }}
    location / {{ return 404; }}
  }}
'''


def tls_server(credentials, settings):
    return f'''  server {{
    listen {env('VPN_BIND_IP')}:{port('VPN_MONITORING_HTTPS_PORT')} ssl;
    server_name {settings.hostname};
    ssl_certificate {BUNDLE};
    ssl_certificate_key {BUNDLE};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    absolute_redirect off;
    access_log off;
{relay.nginx_location(credentials, settings)}    location / {{ return 404; }}
  }}
'''


def write_private(path, data, mode=0o600):
    require(not path.is_symlink(), 'Refusing a symbolic link in WEB TLS state')
    with path.open('wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def check_candidate(container, config, candidate):
    # Existing read-only bind mounts stay in place; validation uses a private
    # temporary configuration in the running container, without a reload.
    temporary = ROOT / ('candidate-' + container + '.conf')
    write_private(temporary, candidate.encode())
    destination = '/tmp/vpn-telegram-web-candidate.conf'
    try:
        command('docker', 'cp', str(temporary), container + ':' + destination)
        command('docker', 'exec', container, 'nginx', '-t', '-c', destination)
    finally:
        command('docker', 'exec', container, 'rm', '-f', destination)
        temporary.unlink(missing_ok=True)


def container_pid(container):
    obj = json.loads(command('docker', 'inspect', container))[0]
    require(obj['State']['Running'], 'The existing nginx container is stopped')
    return obj['Id'], obj['State']['Pid']


def replace_and_reload(container, config, candidate):
    inode = config.stat().st_ino
    previous = config.read_bytes()
    if previous == candidate.encode():
        return
    require(config.is_file() and not config.is_symlink(), 'Unexpected nginx configuration file')
    check_candidate(container, config, candidate)
    before = container_pid(container)
    written = False
    try:
        # HTTP nginx mounts the file inode, so an atomic rename would leave it
        # reading the old file. Test first, then preserve its inode and mode.
        with config.open('r+b') as output:
            require(os.fstat(output.fileno()).st_ino == inode and output.read() == previous,
                    'nginx configuration changed concurrently; preserving it')
            output.seek(0)
            output.write(candidate.encode())
            output.truncate()
            output.flush()
            os.fsync(output.fileno())
            written = True
        command('docker', 'exec', container, 'nginx', '-t', '-c',
                '/etc/nginx/nginx.conf' if config == HTTP_CONFIG else str(config))
        command('docker', 'kill', '--signal=HUP', container)
        require(container_pid(container) == before, 'Unexpected nginx master replacement')
    except BaseException:
        if not written:
            raise
        require(config.stat().st_ino == inode and config.read_bytes() == candidate.encode(),
                'nginx configuration changed after our write; preserving it')
        with config.open('r+b') as output:
            output.write(previous)
            output.truncate()
            output.flush()
            os.fsync(output.fileno())
        command('docker', 'kill', '--signal=HUP', container)
        raise


def check_dns(settings):
    expected = ipaddress.ip_address(env('VPN_ENTRY_ADDRESS'))
    addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(
        settings.hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)}
    require(addresses == {expected}, 'WEB DNS must resolve only to the configured entry address')


def acme_arguments(settings):
    return ['certbot', 'certonly', '--standalone', '--preferred-challenges', 'http',
            '--http-01-address', settings.loopback, '--http-01-port', str(port('VPN_WEB_ACME_PORT')),
            '--config-dir', str(ACME / 'config'), '--work-dir', str(ACME / 'work'),
            '--logs-dir', str(ACME / 'logs'), '--cert-name', 'telegram-web',
            '--domain', settings.hostname, '--agree-tos', '--register-unsafely-without-email',
            '--non-interactive', '--keep-until-expiring']


def certificate_bundle(settings):
    live = ACME / 'config/live/telegram-web'
    chain, key = live / 'fullchain.pem', live / 'privkey.pem'
    command('openssl', 'x509', '-in', str(chain), '-noout', '-checkend', '300')
    command('openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', settings.hostname,
            '-untrusted', str(chain), str(chain))
    public_cert = command('openssl', 'x509', '-in', str(chain), '-pubkey', '-noout')
    public_key = command('openssl', 'pkey', '-in', str(key), '-pubout')
    require(public_cert == public_key, 'WEB certificate and private key do not match')
    return chain.read_bytes() + b'\n' + key.read_bytes()


def verify_https(settings, expected_fingerprint):
    last = None
    for _ in range(30):
        try:
            raw = socket.create_connection((settings.loopback, port('VPN_MONITORING_HTTPS_PORT')), timeout=5)
            with ssl.create_default_context().wrap_socket(raw, server_hostname=settings.hostname) as tls:
                require(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() == expected_fingerprint,
                        'WEB nginx is still serving a different certificate')
                tls.sendall(('GET / HTTP/1.1\r\nHost: ' + settings.hostname
                             + '\r\nConnection: close\r\n\r\n').encode())
                require(tls.recv(2048).startswith(b'HTTP/1.1 404'), 'Unexpected WEB TLS default response')
            return
        except (OSError, RuntimeError) as error:
            last = error
            time.sleep(.2)
    raise RuntimeError('WEB TLS verification failed') from last


def persistence_files(credentials_file):
    service = f'''[Unit]
Description=Renew the isolated Telegram WEB certificate
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/python3 -B {ROOT}/install_web_tls.py renew --credentials {ROOT}/credentials.json
StandardOutput=null
StandardError=null
'''
    timer = f'''[Unit]
Description=Renew the Telegram WEB certificate daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
'''
    files = {ROOT / name: Path(__file__).with_name(name).read_bytes() for name in
             ('install_web_tls.py', 'install_web_proxy.py', 'install_grafana_https.py', 'vpn_env.py')}
    files[ROOT / 'vpn.env.json'] = json.dumps(configured_values()).encode()
    files[ROOT / 'credentials.json'] = credentials_file.read_bytes()
    for extension, content in (('service', service), ('timer', timer)):
        files[Path('/etc/systemd/system') / (UNIT + '.' + extension)] = content.encode()
    return files


def preflight_persistence(files):
    for target, content in files.items():
        require(not target.is_symlink(), 'Unexpected symbolic link in WEB certificate files')
        if target.parent != Path('/etc/systemd/system'):
            continue
        require(not target.exists() or target.read_bytes() == content,
                'An unrelated WEB certificate unit already exists')
        loaded = command('systemctl', 'show', '--property=FragmentPath', '--value', target.name).decode().strip()
        require(not loaded or loaded == str(target), 'WEB certificate unit is loaded from another path')


def persist(files):
    previous = {path: path.read_bytes() if path.exists() else None for path in files}
    written = []
    timer_created = previous[Path('/etc/systemd/system') / (UNIT + '.timer')] is None
    try:
        preflight_persistence(files)
        for target, content in files.items():
            write_private(target, content, 0o644 if target.parent == Path('/etc/systemd/system') else 0o600)
            written.append(target)
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', UNIT + '.timer')
    except BaseException:
        if timer_created and Path('/etc/systemd/system') / (UNIT + '.timer') in written:
            command('systemctl', 'disable', '--now', UNIT + '.timer')
        for target in reversed(written):
            require(target.read_bytes() == files[target], 'WEB timer file changed concurrently; preserving it')
            if previous[target] is None:
                target.unlink()
            else:
                write_private(target, previous[target],
                              0o644 if target.parent == Path('/etc/systemd/system') else 0o600)
        command('systemctl', 'daemon-reload')
        raise


def install(credentials_file, renew=False):
    settings = relay.endpoint_settings()
    credentials = relay.read_private(credentials_file)
    require(len({settings.port, settings.admin_port, settings.backend_port,
                 port('VPN_WEB_ACME_PORT')}) == 4, 'ACME and relay ports must be distinct')
    if not renew:
        check_dns(settings)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    info = ROOT.lstat()
    require(ROOT.is_dir() and not ROOT.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o077,
            'Unsafe WEB TLS state directory')
    with (ROOT / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        command('certbot', '--version')
        with socket.socket() as listener:
            listener.bind((settings.loopback, port('VPN_WEB_ACME_PORT')))
        persistent = persistence_files(credentials_file) if not renew else None
        if persistent:
            preflight_persistence(persistent)
        http_before, https_before = HTTP_CONFIG.read_text(), HTTPS_CONFIG.read_text()
        http_candidate = insert_server(http_before, challenge_server(settings))
        https_candidate = insert_server(https_before, tls_server(credentials, settings))
        old_bundle = BUNDLE.read_bytes() if BUNDLE.exists() else None
        grafana_fingerprint = grafana.source_fingerprint(env('VPN_ENTRY_ADDRESS'))
        grafana.health(env('VPN_ENTRY_ADDRESS'), grafana_fingerprint)
        for label, content in (('http', http_before), ('https', https_before)):
            backup = ROOT / (label + '-before.conf')
            if not backup.exists():
                write_private(backup, content.encode())
        try:
            replace_and_reload(HTTP_CONTAINER, HTTP_CONFIG, http_candidate)
            # Standalone Certbot binds only a private loopback port. Existing
            # public HTTP/HTTPS listeners and all VPN services remain running.
            command(*acme_arguments(settings), timeout=180)
            data = certificate_bundle(settings)
            expected = hashlib.sha256(command('openssl', 'x509', '-in',
                str(ACME / 'config/live/telegram-web/fullchain.pem'), '-outform', 'DER')).hexdigest()
            changed = data != old_bundle
            if changed:
                write_private(BUNDLE, data, 0o600)
            candidate = https_candidate
            replace_and_reload(HTTPS_CONTAINER, HTTPS_CONFIG, candidate)
            if changed and candidate == https_before:
                command('docker', 'exec', HTTPS_CONTAINER, 'nginx', '-t', '-c', str(HTTPS_CONFIG))
                command('docker', 'kill', '--signal=HUP', HTTPS_CONTAINER)
            verify_https(settings, expected)
            grafana.health(env('VPN_ENTRY_ADDRESS'), grafana_fingerprint)
            if not renew:
                persist(persistent)
        except BaseException:
            require(HTTP_CONFIG.read_text() in (http_before, http_candidate)
                    and HTTPS_CONFIG.read_text() in (https_before, https_candidate),
                    'nginx configuration changed outside this transaction; preserving state for review')
            if old_bundle is None:
                BUNDLE.unlink(missing_ok=True)
            else:
                write_private(BUNDLE, old_bundle, 0o600)
            replace_and_reload(HTTPS_CONTAINER, HTTPS_CONFIG, https_before)
            # A failed certificate-only rotation has an unchanged nginx config;
            # explicitly reread the restored certificate in that case as well.
            command('docker', 'exec', HTTPS_CONTAINER, 'nginx', '-t', '-c', str(HTTPS_CONFIG))
            command('docker', 'kill', '--signal=HUP', HTTPS_CONTAINER)
            replace_and_reload(HTTP_CONTAINER, HTTP_CONFIG, http_before)
            raise
    return {'web_tls': 'renewed' if renew else 'installed', 'trusted_hostname_tls': True,
            'vpn_restarted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'renew'])
    parser.add_argument('--credentials', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run the WEB TLS installer as root')
        print(json.dumps(install(args.credentials, args.action == 'renew')))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'install-web-tls: ' + detail + '\n')


if __name__ == '__main__':
    main()
