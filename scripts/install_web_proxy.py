#!/usr/bin/env python3
"""Install an isolated official Telegram WEB relay; TLS integration is separate."""
import argparse
import base64
from dataclasses import dataclass, replace
import fcntl
import grp
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import time
import uuid

from vpn_env import env, port


SOURCE_COMMIT = 'c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8'
SOURCE_SHA256 = 'a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549'
NAME = 'vpn-telegram-web'
UNIT = NAME + '.service'
RUNTIME = Path('/opt') / NAME
ROOT = Path('/etc') / NAME
BINARY = RUNTIME / 'tproxy-server'
CONFIG = ROOT / 'config.json'
PROFILES = ROOT / 'profiles.json'
TOKEN = ROOT / 'token.key'
MANIFEST = RUNTIME / 'source-manifest.json'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
HOSTNAME_LOCK = Path('/run/lock') / (NAME + '-hostname.lock')
HOSTNAME_BACKUPS = Path('/var/backups') / (NAME + '-hostname')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@dataclass(frozen=True)
class Endpoints:
    hostname: str
    loopback: str
    port: int
    admin_port: int
    backend_port: int
    site_port: int


def endpoint_settings():
    hostname = env('VPN_WEB_PROXY_ADDRESS')
    validate_hostname(hostname)
    loopback = env('VPN_LOOPBACK_IP')
    require(ipaddress.IPv4Address(loopback).is_loopback,
            'WEB relay and admin listeners must use an IPv4 loopback address')
    settings = Endpoints(hostname, loopback, port('VPN_WEB_PROXY_PORT'),
                         port('VPN_WEB_PROXY_ADMIN_PORT'), port('VPN_MTPROTO_DD_PORT'),
                         port('VPN_MONITORING_HTTP_PORT'))
    require(len({settings.port, settings.admin_port, settings.backend_port, settings.site_port}) == 4,
            'WEB relay, admin, MTProxy and site ports must be distinct')
    require(all(number >= 1024 for number in (settings.port, settings.admin_port)),
            'The unprivileged WEB relay requires non-privileged TCP ports')
    require(port('VPN_MONITORING_HTTPS_PORT') == http.client.HTTPS_PORT,
            'Native Telegram WEB clients require the standard HTTPS endpoint')
    return settings


def validate_hostname(value):
    require(isinstance(value, str) and 1 <= len(value) <= 253 and '.' in value
            and value == value.lower() and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                               for label in value.split('.')),
            'WEB proxy requires a canonical lowercase DNS hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise RuntimeError('Native Telegram WEB clients require a DNS hostname')


def read_private(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
            'WEB credentials must be a small owner-only regular JSON file')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'Expected a private WEB credentials object')
    secret = value.get('secret')
    base_path = value.get('base_path')
    require(isinstance(secret, str) and re.fullmatch(r'dd[0-9a-f]{32}', secret) is not None,
            'WEB relay must use the existing padded MTProxy secret')
    require(isinstance(base_path, str) and 1 <= len(base_path) <= 128
            and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', part) for part in base_path.split('/')),
            'WEB co-hosting requires a canonical nonempty base path')
    token = value.get('token_key')
    require(isinstance(token, str) and re.fullmatch(r'[0-9a-f]{64}', token) is not None,
            'WEB relay needs a persistent random signing key')
    return {'secret': secret, 'base_path': base_path, 'token_key': token}


def config_text(credentials, settings):
    value = {
        'public_hostname': settings.hostname, 'base_path': credentials['base_path'],
        'listen': f'{settings.loopback}:{settings.port}',
        'admin_listen': f'{settings.loopback}:{settings.admin_port}',
        'public_upstream': f'http://{settings.loopback}:{settings.site_port}',
        'token_key_file': str(TOKEN), 'profiles_file': str(PROFILES), 'enable_pprof': False,
        'limits': {
            'max_streams_per_session': 16, 'max_closed_stream_ids': 512,
            'max_pending_per_session': 8 * 1024 * 1024,
            'max_pending_global': 32 * 1024 * 1024,
            # The official relay reserves a full uplink batch plus control
            # frames before allocating downlink items; keep headroom for DATA.
            'max_pending_items_per_session': 16384, 'max_pending_items_global': 131072,
            'max_sessions_per_ip': 0, 'max_sessions_global': 32,
            'max_streams_global': 256, 'max_backend_dials_in_flight': 32,
            'new_sessions_per_minute': 120, 'new_sessions_burst': 32,
            'new_streams_per_minute': 1200, 'new_streams_burst': 128,
            'max_bootstraps_per_ip': 0, 'max_bootstraps_global': 128,
            'new_bootstraps_per_minute': 240, 'new_bootstraps_burst': 64, 'max_profiles': 1,
        },
        'timeouts': {'backend_dial': '5s', 'long_poll': '25s', 'reconnect_grace': '2m',
                     'bootstrap_lifetime': '2m', 'read_header': '10s', 'idle': '75s', 'shutdown': '15s'},
    }
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


def profiles_text(credentials, settings):
    return json.dumps({'profiles': [{
        'name': 'vpn-auto', 'secret': credentials['secret'],
        'backend': f'{settings.loopback}:{settings.backend_port}', 'carrier_mode': 'https',
    }]}, sort_keys=True, indent=2) + '\n'


def bridge_capability(credentials, settings):
    context = 'tdesktop-web-proxy-bridge-v2\n' + settings.hostname + '\n' + credentials['base_path']
    digest = hmac.digest(bytes.fromhex(credentials['secret']), context.encode(), 'sha256')
    return base64.urlsafe_b64encode(digest).decode().rstrip('=')


def client_access(credentials, settings):
    from urllib.parse import urlencode
    server = settings.hostname + '/' + credentials['base_path']
    marked = base64.urlsafe_b64encode(b'\x70' + bytes.fromhex(credentials['secret'])).decode().rstrip('=')
    return {'server': server, 'secret': marked,
            'link': 'tg://webproxy?' + urlencode({'server': server, 'secret': marked})}


def nginx_location(credentials, settings):
    # Keep the path, query, Host and browser transport headers byte-for-byte.
    return f'''    location ^~ /{credentials['base_path']}/ {{
      access_log off;
      proxy_pass http://{settings.loopback}:{settings.port};
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_request_buffering off;
      proxy_buffering off;
      proxy_read_timeout 90s;
      proxy_send_timeout 90s;
      client_max_body_size 2m;
    }}
'''


def unit_text():
    return f'''[Unit]
Description=Official Telegram WEB relay through VPN Auto
Wants=network-online.target
After=network-online.target vpn-mtproto-dd.service

[Service]
Type=simple
User={NAME}
Group={NAME}
WorkingDirectory={RUNTIME}
ExecStart={BINARY} -config {CONFIG}
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
UMask=0077
Environment=GOMAXPROCS=1
Environment=GOMEMLIMIT=96MiB
MemoryMax=128M
CPUQuota=50%
TasksMax=48
LimitNOFILE=2048
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''


def command(*args, timeout=30):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('A WEB relay installation check timed out') from None
    require(result.returncode == 0, 'WEB relay installation command failed: ' + args[0])
    return result.stdout


def read_binary(path, expected):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 128 * 1024 * 1024,
            'WEB relay executable must be a regular bounded file')
    data = path.read_bytes()
    require(re.fullmatch(r'[0-9a-f]{64}', expected) is not None
            and hashlib.sha256(data).hexdigest() == expected,
            'WEB relay executable SHA256 mismatch')
    require(len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01'
            and data[18:20] == b'\x3e\x00', 'Expected a Linux amd64 WEB relay executable')
    return data


def check_account():
    account, group = pwd.getpwnam(NAME), grp.getgrnam(NAME)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0
            and account.pw_dir == '/nonexistent' and account.pw_shell.endswith('/nologin'),
            'An unexpected account occupies the WEB relay service name')
    return account.pw_uid, group.gr_gid


def write_new(path, data, mode, group=0, owner=0):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchown(stream.fileno(), owner, group)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def get(settings, admin, path):
    connection = http.client.HTTPConnection(settings.loopback,
                                             settings.admin_port if admin else settings.port, timeout=5)
    try:
        connection.request('GET', path, headers={'Host': settings.hostname})
        response = connection.getresponse()
        return response.status, response.read(1024 * 1024)
    finally:
        connection.close()


def verify_listener(credentials, settings):
    last_error = None
    for _ in range(25):
        try:
            for path in ('/healthz', '/readyz'):
                require(get(settings, True, path)[0] == 200, 'WEB relay private health check failed')
            status, body = get(settings, False, '/' + credentials['base_path']
                               + '/?bridge=' + bridge_capability(credentials, settings))
            require(status == 200 and b'tproxy-android-init' in body and b'bootstrap=' in body,
                    'WEB bridge authentication check failed')
            _, rejected = get(settings, False, '/' + credentials['base_path'] + '/?bridge=wrong')
            require(b'tproxy-android-init' not in rejected and b'bootstrap=' not in rejected,
                    'WEB relay exposed a bridge for an invalid capability')
            return
        except (OSError, http.client.HTTPException) as error:
            last_error = error
            time.sleep(.2)
    raise RuntimeError('The WEB relay did not become ready') from last_error


def file_metadata(path, uid, gid):
    if path in (PROFILES, TOKEN):
        # Upstream rejects group-readable secrets. ProtectSystem=strict keeps
        # these service-owned owner-only files read-only inside the unit.
        return uid, gid, 0o600
    return 0, (gid if path == CONFIG else 0), (0o755 if path == BINARY else 0o644 if path == UNIT_PATH else 0o640)


def verify_files(files, uid, gid):
    for directory, expected_gid, mode in ((RUNTIME, 0, 0o755), (ROOT, gid, 0o750)):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == expected_gid
                and stat.S_IMODE(info.st_mode) == mode, 'Unexpected existing WEB relay directory')
    for path, data in files.items():
        info = path.lstat()
        owner, group, mode = file_metadata(path, uid, gid)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_gid == group
                and stat.S_IMODE(info.st_mode) == mode and path.read_bytes() == data,
                'A different WEB relay installation exists; refusing to overwrite it')
    require(set(RUNTIME.iterdir()) == {BINARY, MANIFEST} and set(ROOT.iterdir()) == {CONFIG, PROFILES, TOKEN},
            'Unexpected existing WEB relay files; preserving them for inspection')


def installation_files(binary, binary_sha256, credentials, settings):
    return {BINARY: read_binary(binary, binary_sha256), CONFIG: config_text(credentials, settings).encode(),
             PROFILES: profiles_text(credentials, settings).encode(), TOKEN: bytes.fromhex(credentials['token_key']),
             UNIT_PATH: unit_text().encode(),
             MANIFEST: (json.dumps({'source_commit': SOURCE_COMMIT, 'source_sha256': SOURCE_SHA256,
                                    'binary_sha256': binary_sha256}, sort_keys=True) + '\n').encode()}


def check_unit():
    require(command('systemctl', 'show', '--property=FragmentPath', '--value', UNIT).decode().strip()
            == str(UNIT_PATH), 'WEB relay service uses an unexpected unit fragment')
    command('systemctl', 'is-active', '--quiet', UNIT)


def install(binary, binary_sha256, secrets_file):
    settings, credentials = endpoint_settings(), read_private(secrets_file)
    files = installation_files(binary, binary_sha256, credentials, settings)
    if any(os.path.lexists(path) for path in (RUNTIME, ROOT, UNIT_PATH)):
        uid, gid = check_account()
        verify_files(files, uid, gid)
        check_unit()
        verify_listener(credentials, settings)
        return {'already_installed': True, 'unit': UNIT}
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The WEB relay service name is already in use')
    with socket.create_connection((settings.loopback, settings.backend_port), timeout=3):
        pass
    with socket.socket() as listener, socket.socket() as admin_listener:
        listener.bind((settings.loopback, settings.port))
        admin_listener.bind((settings.loopback, settings.admin_port))
    created, account_created = [], False
    try:
        try:
            check_account()
        except KeyError:
            require(not any(group.gr_name == NAME for group in grp.getgrall()),
                    'An unrelated group occupies the WEB relay service name')
            command('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', NAME)
            account_created = True
        uid, gid = check_account()
        for directory, mode, group in ((RUNTIME, 0o755, 0), (ROOT, 0o750, gid)):
            directory.mkdir(mode=mode)
            created.append(directory)
            os.chown(directory, 0, group)
            directory.chmod(mode)
        for path, data in files.items():
            owner, group, mode = file_metadata(path, uid, gid)
            write_new(path, data, mode, group, owner)
            created.append(path)
        command('runuser', '-u', NAME, '--', str(BINARY), '-config', str(CONFIG), '-check')
        command('systemd-analyze', 'verify', str(UNIT_PATH))
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', UNIT)
        verify_listener(credentials, settings)
        command('systemctl', 'is-active', '--quiet', UNIT)
    except BaseException:
        own_unit = UNIT_PATH in created and UNIT_PATH.is_file() and UNIT_PATH.read_bytes() == files[UNIT_PATH]
        if own_unit:
            try:
                command('systemctl', 'disable', '--now', UNIT)
            except RuntimeError:
                raise RuntimeError('Could not stop the new WEB relay; its files were preserved') from None
        for path in reversed(created):
            if path in files:
                require(path.is_file() and not path.is_symlink() and path.read_bytes() == files[path],
                        'A WEB relay file changed during installation; preserving it')
                path.unlink()
            else:
                path.rmdir()
        if own_unit:
            command('systemctl', 'daemon-reload')
        if account_created:
            command('userdel', NAME)
        raise
    return {'installed': True, 'unit': UNIT, 'loopback_only': True,
            'tls_integration_pending': True, 'existing_services_restarted': False}


def same_file(path, previous, identity):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity
            and path.read_bytes() == previous)


def retarget_hostname(binary, binary_sha256, secrets_file, previous_hostname):
    """Change only an explicitly expected WEB hostname, retaining every secret."""
    validate_hostname(previous_hostname)
    settings, credentials = endpoint_settings(), read_private(secrets_file)
    desired = installation_files(binary, binary_sha256, credentials, settings)
    previous_settings = replace(settings, hostname=previous_hostname)
    previous = desired | {CONFIG: config_text(credentials, previous_settings).encode()}
    before, after = json.loads(previous[CONFIG]), json.loads(desired[CONFIG])
    before.pop('public_hostname')
    after.pop('public_hostname')
    require(before == after, 'The requested WEB migration changes more than its hostname')
    with HOSTNAME_LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        uid, gid = check_account()
        if CONFIG.read_bytes() == desired[CONFIG]:
            verify_files(desired, uid, gid)
            check_unit()
            verify_listener(credentials, settings)
            return {'already_retargeted': True, 'unit': UNIT, 'existing_services_restarted': False}
        require(previous_hostname != settings.hostname, 'The previous WEB hostname already equals the desired hostname')
        verify_files(previous, uid, gid)
        check_unit()
        info = CONFIG.lstat()
        identity = (info.st_dev, info.st_ino)
        HOSTNAME_BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup_info = HOSTNAME_BACKUPS.lstat()
        require(stat.S_ISDIR(backup_info.st_mode) and backup_info.st_uid == os.geteuid()
                and not backup_info.st_mode & 0o077, 'Unsafe WEB hostname backup directory')
        nonce = uuid.uuid4().hex
        backup = HOSTNAME_BACKUPS / nonce
        backup.mkdir(mode=0o700)
        write_new(backup / 'config.json', previous[CONFIG], 0o600)
        candidate = ROOT / ('.hostname-' + nonce + '.json')
        candidate_identity = None
        changed = False
        try:
            write_new(candidate, desired[CONFIG], 0o640, gid)
            candidate_info = candidate.lstat()
            candidate_identity = (candidate_info.st_dev, candidate_info.st_ino)
            command('runuser', '-u', NAME, '--', str(BINARY), '-config', str(candidate), '-check')
            require(same_file(CONFIG, previous[CONFIG], identity),
                    'WEB configuration changed concurrently; preserving it')
            require(same_file(candidate, desired[CONFIG], candidate_identity),
                    'WEB hostname candidate changed concurrently; preserving it')
            os.replace(candidate, CONFIG)
            changed = True
            command('systemctl', 'restart', UNIT)
            verify_files(desired, uid, gid)
            check_unit()
            verify_listener(credentials, settings)
        except BaseException:
            if changed:
                require(same_file(CONFIG, desired[CONFIG], candidate_identity),
                        'WEB configuration changed after migration; backup retained for review')
                rollback_candidate = ROOT / ('.rollback-' + nonce + '.json')
                write_new(rollback_candidate, previous[CONFIG], 0o640, gid)
                os.replace(rollback_candidate, CONFIG)
                try:
                    command('systemctl', 'restart', UNIT)
                    verify_files(previous, uid, gid)
                    check_unit()
                    verify_listener(credentials, previous_settings)
                except BaseException:
                    raise RuntimeError('The previous WEB config was restored; its dedicated service needs inspection') from None
            raise
        finally:
            if candidate.exists():
                require(candidate_identity is not None and same_file(candidate, desired[CONFIG], candidate_identity),
                        'The WEB hostname candidate changed; preserving it for review')
                candidate.unlink()
        return {'retargeted': True, 'unit': UNIT, 'only_web_service_restarted': True,
                'secrets_unchanged': True, 'base_path_unchanged': True, 'backup': str(backup),
                'vpn_services_restarted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'retarget-hostname'])
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--secrets-file', type=Path, required=True)
    parser.add_argument('--previous-hostname')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run the WEB relay installer as root on the entry server')
        if args.action == 'retarget-hostname':
            require(args.previous_hostname, 'An explicit previous WEB hostname is required')
            result = retarget_hostname(args.binary, args.binary_sha256, args.secrets_file, args.previous_hostname)
        else:
            require(args.previous_hostname is None, 'The install action does not accept a previous hostname')
            result = install(args.binary, args.binary_sha256, args.secrets_file)
        print(json.dumps(result))
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'install-web-proxy: ' + detail + '\n')


if __name__ == '__main__':
    main()
