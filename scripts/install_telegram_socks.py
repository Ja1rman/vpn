#!/usr/bin/env python3
"""Install independent Telegram SOCKS and fixed MTProto TCP frontends."""
import argparse
from dataclasses import dataclass
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import time


NAME = 'vpn-telegram-socks'
UNIT = NAME + '.service'
RUNTIME = Path('/opt') / NAME
CONFIG_DIRECTORY = Path('/etc') / NAME
BINARY = RUNTIME / 'xray'
CONFIG = CONFIG_DIRECTORY / 'config.json'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
SOURCE_BINARY = Path('/opt/vpn-balancer/xray')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@dataclass(frozen=True)
class Endpoints:
    bind: str
    loopback: str
    public: str
    port: int
    pool_port: int
    mtproto_public_port: int
    mtproto_port: int


def endpoint_settings():
    from vpn_env import env, port

    settings = Endpoints(env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'),
                         env('VPN_ENTRY_ADDRESS'), port('VPN_TELEGRAM_SOCKS_PORT'),
                         port('VPN_FAILOVER_SOCKS_PORT'), port('VPN_MTPROTO_PUBLIC_PORT'),
                         port('VPN_MTPROTO_PORT'))
    require(ipaddress.IPv4Address(settings.loopback).is_loopback,
            'The VPN Auto upstream must use an IPv4 loopback address')
    for address in (settings.bind, settings.public):
        parsed = ipaddress.IPv4Address(address)
        require(not parsed.is_multicast, 'Expected a unicast or unspecified IPv4 address')
    require(all(value >= 1024 for value in (settings.port, settings.mtproto_public_port)),
            'The unprivileged frontends require non-privileged TCP ports')
    require(len({settings.port, settings.pool_port, settings.mtproto_public_port, settings.mtproto_port}) == 4,
            'The Telegram frontends and their existing backends must have distinct ports')
    return settings


def read_secrets(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
            'Credentials must be stored in a private regular JSON file')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'Expected a credentials JSON object')
    require(not ('username' in value and 'user' in value), 'Use one username field')
    username, password = value.get('username', value.get('user')), value.get('password')
    require(isinstance(username, str) and 1 <= len(username) <= 64
            and all(character.isascii() and (character.isalnum() or character in '._-')
                    for character in username), 'Invalid SOCKS username')
    require(isinstance(password, str) and 24 <= len(password) <= 128
            and all(33 <= ord(character) <= 126 for character in password),
            'Use a long printable ASCII SOCKS password without whitespace')
    return {'username': username, 'password': password}


def config_text(credentials, settings):
    config = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': 'telegram-socks', 'listen': settings.bind, 'port': settings.port,
            'protocol': 'socks',
            'settings': {'auth': 'password', 'udp': False,
                         'accounts': [{'user': credentials['username'], 'pass': credentials['password']}]},
            # Never reinterpret a FakeTLS hostname as the SOCKS destination.
            'sniffing': {'enabled': False},
        }, {
            'tag': 'mtproto-tunnel', 'listen': settings.bind, 'port': settings.mtproto_public_port,
            'protocol': 'tunnel',
            'settings': {'address': settings.loopback, 'port': settings.mtproto_port,
                         'network': 'tcp', 'followRedirect': False},
            'sniffing': {'enabled': False},
        }],
        'outbounds': [{
            'tag': 'vpn-auto', 'protocol': 'socks',
            'settings': {'servers': [{'address': settings.loopback, 'port': settings.pool_port}]},
        }, {
            'tag': 'mtproto-loopback', 'protocol': 'freedom',
            # Defense in depth: this outbound can never dial an arbitrary target.
            'settings': {'redirect': f'{settings.loopback}:{settings.mtproto_port}'},
        }],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': ['mtproto-tunnel'], 'outboundTag': 'mtproto-loopback'},
            {'type': 'field', 'inboundTag': ['telegram-socks'], 'outboundTag': 'vpn-auto'},
        ]},
    }
    return json.dumps(config, ensure_ascii=True, indent=2) + '\n'


def unit_text():
    return f'''[Unit]
Description=Telegram SOCKS through VPN Auto and fixed MTProto TCP forwarding
Wants=network-online.target
After=network-online.target vpn-failover-pool.service

[Service]
Type=simple
User={NAME}
Group={NAME}
WorkingDirectory={RUNTIME}
ExecStart={BINARY} run -config {CONFIG}
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
Environment=GOMAXPROCS=1
Environment=GOMEMLIMIT=64MiB
MemoryMax=96M
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

[Install]
WantedBy=multi-user.target
'''


def command(*args, timeout=30):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('A Telegram SOCKS installation check timed out') from None
    require(result.returncode == 0, 'Telegram SOCKS installation command failed: ' + args[0])
    return result.stdout


def read_binary():
    info = SOURCE_BINARY.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o111 and 0 < info.st_size <= 128 * 1024 * 1024,
            'Expected the root-owned existing VPN pool executable')
    value = SOURCE_BINARY.read_bytes()
    require(len(value) >= 20 and value[:6] == b'\x7fELF\x02\x01'
            and value[18:20] == b'\x3e\x00', 'Expected the existing Linux amd64 Xray executable')
    return value


def check_account():
    account, group = pwd.getpwnam(NAME), grp.getgrnam(NAME)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0
            and account.pw_dir == '/nonexistent' and account.pw_shell.endswith('/nologin'),
            'An unexpected account occupies the Telegram SOCKS service name')
    return account.pw_uid, group.gr_gid


def read_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        require(bool(chunk), 'The Telegram SOCKS check received a closed connection')
        result.extend(chunk)
    return bytes(result)


def pool_available(settings):
    with socket.create_connection((settings.loopback, settings.pool_port), timeout=3) as connection:
        connection.sendall(b'\x05\x01\x00')
        require(read_exact(connection, 2) == b'\x05\x00', 'The existing VPN Auto SOCKS pool did not answer')


def mtproto_available(settings):
    with socket.create_connection((settings.loopback, settings.mtproto_port), timeout=3):
        pass


def verify_listener(credentials, settings):
    # Test only this new listener: authentication is mandatory and credentials work.
    target = settings.loopback if ipaddress.IPv4Address(settings.bind).is_unspecified else settings.bind
    last_error = None
    for _ in range(25):
        try:
            with socket.create_connection((target, settings.port), timeout=2) as connection:
                connection.sendall(b'\x05\x01\x00')
                require(read_exact(connection, 2) == b'\x05\xff',
                        'The Telegram SOCKS listener unexpectedly permits unauthenticated access')
            with socket.create_connection((target, settings.port), timeout=2) as connection:
                connection.sendall(b'\x05\x01\x02')
                require(read_exact(connection, 2) == b'\x05\x02',
                        'The Telegram SOCKS listener did not request password authentication')
                username, password = credentials['username'].encode(), credentials['password'].encode()
                connection.sendall(b'\x01' + bytes([len(username)]) + username
                                   + bytes([len(password)]) + password)
                require(read_exact(connection, 2) == b'\x01\x00',
                        'The Telegram SOCKS credentials were rejected')
            with socket.create_connection((target, settings.mtproto_public_port), timeout=2):
                pass
            return
        except OSError as error:
            last_error = error
            time.sleep(.2)
    raise RuntimeError('The Telegram SOCKS frontend did not open its listener') from last_error


def write_new(path, value, mode, group=0):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchown(stream.fileno(), 0, group)
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def verify_existing(files, credentials, settings):
    _, gid = check_account()
    expected = {RUNTIME: (0, 0o755), CONFIG_DIRECTORY: (gid, 0o750),
                BINARY: (0, 0o755), CONFIG: (gid, 0o640), UNIT_PATH: (0, 0o644)}
    for path, (group, mode) in expected.items():
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == 0 and info.st_gid == group
                and stat.S_IMODE(info.st_mode) == mode,
                'Existing Telegram SOCKS files have unexpected ownership or permissions')
    require(all(path.is_file() and path.read_bytes() == value for path, value in files.items()),
            'A different Telegram SOCKS installation already exists; refusing to overwrite it')
    command('systemctl', 'is-active', '--quiet', UNIT)
    verify_listener(credentials, settings)


def install(secrets_file):
    settings, credentials = endpoint_settings(), read_secrets(secrets_file)
    files = {BINARY: read_binary(), CONFIG: config_text(credentials, settings).encode(),
             UNIT_PATH: unit_text().encode()}
    if any(os.path.lexists(path) for path in (RUNTIME, CONFIG_DIRECTORY, UNIT_PATH)):
        require(all(os.path.lexists(path) for path in (*files, RUNTIME, CONFIG_DIRECTORY)),
                'An incomplete or unrelated installation occupies the Telegram SOCKS paths')
        verify_existing(files, credentials, settings)
        return {'already_installed': True, 'unit': UNIT}
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The Telegram SOCKS service name is already in use')
    pool_available(settings)
    mtproto_available(settings)
    with socket.socket() as socks_listener, socket.socket() as mtproto_listener:
        socks_listener.bind((settings.bind, settings.port))
        mtproto_listener.bind((settings.bind, settings.mtproto_public_port))
    created, account_created = [], False
    try:
        try:
            check_account()
        except KeyError:
            require(not any(group.gr_name == NAME for group in grp.getgrall()),
                    'An unrelated group occupies the Telegram SOCKS service name')
            command('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', NAME)
            account_created = True
        _, gid = check_account()
        for directory, mode, group in ((RUNTIME, 0o755, 0), (CONFIG_DIRECTORY, 0o750, gid)):
            directory.mkdir(mode=mode)
            created.append(directory)
            os.chown(directory, 0, group)
            directory.chmod(mode)
        for path, value in files.items():
            write_new(path, value, 0o640 if path == CONFIG else 0o755 if path == BINARY else 0o644,
                      gid if path == CONFIG else 0)
            created.append(path)
        command(str(BINARY), 'run', '-test', '-config', str(CONFIG))
        command('systemd-analyze', 'verify', str(UNIT_PATH))
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', UNIT)
        verify_listener(credentials, settings)
        command('systemctl', 'is-active', '--quiet', UNIT)
    except BaseException:
        # Stop only a unit whose complete bytes are still ours. Never touch VPN units.
        own_unit = UNIT_PATH in created and UNIT_PATH.is_file() and UNIT_PATH.read_bytes() == files[UNIT_PATH]
        if own_unit:
            try:
                command('systemctl', 'disable', '--now', UNIT)
            except RuntimeError:
                # Preserve the private payload if stopping our new unit failed.
                raise RuntimeError('Could not stop the new Telegram SOCKS unit; installation files were preserved') from None
        for path in reversed(created):
            if path in files:
                require(path.is_file() and not path.is_symlink() and path.read_bytes() == files[path],
                        'A Telegram SOCKS file changed during installation; preserving it for inspection')
                path.unlink()
            else:
                path.rmdir()
        if own_unit:
            command('systemctl', 'daemon-reload')
        if account_created:
            command('userdel', NAME)
        raise
    return {'installed': True, 'unit': UNIT, 'config': str(CONFIG),
            'mtproto_tcp_forward': True, 'existing_services_restarted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install'])
    parser.add_argument('--secrets-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run this installer as root on the entry server')
        print(json.dumps(install(args.secrets_file)))
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'install-telegram-socks: ' + detail + '\n')


if __name__ == '__main__':
    main()
