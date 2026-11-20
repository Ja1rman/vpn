#!/usr/bin/env python3
"""Install a separate secure-only MTProto proxy through the existing VPN Auto pool."""
import argparse
from dataclasses import dataclass
import grp
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import socket
import stat
import subprocess
import tarfile
import time
import zipfile


SOURCE_COMMIT = 'bd5b03cd998eee5e916c5fcea8519d6d2c331d4d'
SOURCE_URL = 'https://codeload.github.com/alexbers/mtprotoproxy/tar.gz/' + SOURCE_COMMIT
ARCHIVE_SHA256 = '81d3bc9bdaa4cf0d02bc03d65b5b2dd15b3ecfae7a9162df6ccf074e26318588'
SOCKS_WHEEL_URL = ('https://files.pythonhosted.org/packages/8d/59/'
                   'b4572118e098ac8e46e399a1dd0f2d85403ce8bbaad9ec79373ed6badaf9/'
                   'PySocks-1.7.1-py3-none-any.whl')
SOCKS_WHEEL_SHA256 = '2725bd0a9925919b9b51739eea5f9e2bae91e83288108a9ad338b2e3a4435ee5'
NAME = 'vpn-mtproto-dd'
UNIT = NAME + '.service'
RUNTIME = Path('/opt') / NAME
VENDOR = RUNTIME / 'vendor'
SOURCE = VENDOR / 'source'
SOCKS = VENDOR / 'pysocks'
CONFIG_DIRECTORY = Path('/etc') / NAME
CONFIG = CONFIG_DIRECTORY / 'config.py'
MANIFEST = RUNTIME / 'source-manifest.json'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
PYTHON = Path('/usr/bin/python3')


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


def endpoint_settings():
    from vpn_env import env, port

    settings = Endpoints(env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'), env('VPN_ENTRY_ADDRESS'),
                         port('VPN_MTPROTO_DD_PORT'), port('VPN_FAILOVER_SOCKS_PORT'))
    require(ipaddress.IPv4Address(settings.loopback).is_loopback,
            'The VPN Auto upstream must be an IPv4 loopback address')
    for address in (settings.bind, settings.public):
        require(not ipaddress.IPv4Address(address).is_multicast, 'Expected a unicast IPv4 address')
    require(settings.port >= 1024 and settings.port != settings.pool_port,
            'The independent DD listener needs a distinct non-privileged TCP port')
    return settings


def read_secrets(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
            'The existing EE secret must be in a private regular JSON file')
    value = json.loads(path.read_text())
    encoded = value.get('secret') if isinstance(value, dict) else None
    require(isinstance(encoded, str) and len(encoded) <= 1024 and encoded.isascii(),
            'Expected an existing hexadecimal EE secret')
    try:
        raw = bytes.fromhex(encoded)
    except ValueError:
        raise RuntimeError('Expected an existing hexadecimal EE secret') from None
    require(len(raw) > 17 and raw[0] == 0xee and len(encoded) == len(raw) * 2,
            'Expected an existing hexadecimal EE secret with its cover domain')
    try:
        domain = raw[17:].decode('ascii')
    except UnicodeDecodeError:
        raise RuntimeError('The existing EE secret has an invalid cover domain') from None
    require(0 < len(domain) <= 253 and all(character.isalnum() or character in '.-' for character in domain),
            'The existing EE secret has an invalid cover domain')
    key = raw[1:17]
    require(len(set(key)) > 1, 'The existing MTProto secret must not be a repeated-byte placeholder')
    return key.hex()


def config_text(key, settings):
    # This is an entirely rendered private file; the daemon never reads operator environment variables.
    values = {
        'PORT': settings.port,
        'USERS': {'vpn': key},
        'MODES': {'classic': False, 'secure': True, 'tls': False},
        'SOCKS5_HOST': settings.loopback,
        'SOCKS5_PORT': settings.pool_port,
        'SOCKS5_USER': None,
        'SOCKS5_PASS': None,
        'USE_MIDDLE_PROXY': False,
        'PREFER_IPV6': False,
        'FAST_MODE': False,
        'REPLAY_CHECK_LEN': 65536,
        'IGNORE_TIME_SKEW': False,
        'CLIENT_IPS_LEN': 0,
        'STATS_PRINT_PERIOD': 600,
        'GET_TIME_PERIOD': 0,
        'MASK': False,
        'MY_DOMAIN': settings.public,
        'LISTEN_ADDR_IPV4': settings.bind,
        'LISTEN_ADDR_IPV6': None,
        'LISTEN_UNIX_SOCK': '',
        'METRICS_PORT': None,
        'USER_MAX_TCP_CONNS': {'vpn': 128},
    }
    return ''.join(name + ' = ' + repr(value) + '\n' for name, value in values.items())


def unit_text():
    return f'''[Unit]
Description=Secure MTProto through VPN Auto
Wants=network-online.target
After=network-online.target vpn-failover-pool.service

[Service]
Type=simple
User={NAME}
Group={NAME}
WorkingDirectory={SOURCE}
ExecStart={PYTHON} -B {SOURCE / 'mtprotoproxy.py'} {CONFIG}
Environment=PYTHONPATH={SOCKS}
Environment=PYTHONDONTWRITEBYTECODE=1
StandardInput=null
StandardOutput=null
StandardError=null
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
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

[Install]
WantedBy=multi-user.target
'''


def command(*args, timeout=30):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('An MTProto DD installation check timed out') from None
    require(result.returncode == 0, 'MTProto DD installation command failed: ' + str(args[0]))
    return result.stdout


def check_dependency():
    resolved = PYTHON.resolve(strict=True)
    info = resolved.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o111, 'Expected a root-owned system Python interpreter')
    # Do not install anything into system Python or print a failed import's traceback.
    command(str(PYTHON), '-I', '-B', '-c',
            'from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes; '
            'Cipher(algorithms.AES(bytes(32)), modes.CTR(bytes(16))).encryptor()')


def pinned_bytes(path, expected):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 16 * 1024 * 1024,
            'Expected a regular pinned dependency archive')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected, 'A dependency archive SHA256 does not match its pin')
    return body


def safe_parts(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and '\\' not in name and '\x00' not in name
            and '..' not in path.parts and bool(path.parts), 'Unsafe dependency archive member')
    return path.parts


def read_assets(archive, socks_wheel):
    source_body = pinned_bytes(archive, ARCHIVE_SHA256)
    wheel_body = pinned_bytes(socks_wheel, SOCKS_WHEEL_SHA256)
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(source_body), mode='r:gz') as source:
        for member in source.getmembers():
            parts = safe_parts(member.name)
            require(parts[0] == 'mtprotoproxy-' + SOURCE_COMMIT, 'Unexpected source archive directory')
            require(member.isdir() or member.isfile(), 'Unsupported dependency archive member type')
            if member.isdir():
                continue
            require(len(parts) > 1 and 0 <= member.size <= 4 * 1024 * 1024,
                    'Unexpected dependency archive file size')
            path = SOURCE.joinpath(*parts[1:])
            require(path not in files, 'Duplicate dependency archive member')
            with source.extractfile(member) as stream:
                files[path] = stream.read()
            total += len(files[path])
            require(total <= 16 * 1024 * 1024, 'Dependency extraction exceeds its size limit')
    with zipfile.ZipFile(io.BytesIO(wheel_body)) as wheel:
        for member in wheel.infolist():
            parts = safe_parts(member.filename)
            require(not stat.S_ISLNK(member.external_attr >> 16), 'Unsupported dependency archive member type')
            if member.is_dir():
                continue
            require(member.file_size <= 4 * 1024 * 1024, 'Unexpected dependency archive file size')
            path = SOCKS.joinpath(*parts)
            require(path not in files, 'Duplicate dependency archive member')
            files[path] = wheel.read(member)
            total += len(files[path])
            require(total <= 16 * 1024 * 1024, 'Dependency extraction exceeds its size limit')
    require(SOURCE / 'mtprotoproxy.py' in files and SOCKS / 'socks.py' in files,
            'The pinned dependencies are incomplete')
    for path, body in files.items():
        if path.suffix == '.py':
            compile(body, '<pinned dependency>', 'exec')
    manifest = {'source_commit': SOURCE_COMMIT, 'source_url': SOURCE_URL,
                'archive_sha256': ARCHIVE_SHA256, 'socks_wheel_url': SOCKS_WHEEL_URL,
                'socks_wheel_sha256': SOCKS_WHEEL_SHA256}
    files[MANIFEST] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    return files


def check_account():
    account, group = pwd.getpwnam(NAME), grp.getgrnam(NAME)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0
            and account.pw_dir == '/nonexistent' and account.pw_shell.endswith('/nologin'),
            'An unexpected account occupies the MTProto DD service name')
    return account.pw_uid, group.gr_gid


def pool_available(settings):
    with socket.create_connection((settings.loopback, settings.pool_port), timeout=3) as connection:
        connection.sendall(b'\x05\x01\x00')
        reply = b''
        while len(reply) < 2:
            chunk = connection.recv(2 - len(reply))
            require(bool(chunk), 'The VPN Auto SOCKS pool closed its greeting')
            reply += chunk
        require(reply == b'\x05\x00', 'The VPN Auto SOCKS pool did not answer its greeting')


def verify_listener(settings):
    # Match the listening socket to this unit's MainPID, without logging peer addresses or sending payloads.
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        pid = command('systemctl', 'show', '--property=MainPID', '--value', UNIT).strip()
        if pid.isdigit() and int(pid) > 0:
            try:
                sockets = {os.readlink(path) for path in (Path('/proc') / pid.decode() / 'fd').iterdir()}
                for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                    fields = line.split()
                    if (fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == settings.port
                            and 'socket:[' + fields[9] + ']' in sockets):
                        command('systemctl', 'is-active', '--quiet', UNIT)
                        return
            except (FileNotFoundError, ProcessLookupError):
                pass
        time.sleep(.2)
    raise RuntimeError('The new MTProto DD unit did not open its own listener')


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


def directories_for(files):
    directories = {RUNTIME, VENDOR, SOURCE, SOCKS, CONFIG_DIRECTORY}
    for path in files:
        if path.is_relative_to(RUNTIME):
            parent = path.parent
            while parent != RUNTIME:
                directories.add(parent)
                parent = parent.parent
    return sorted(directories, key=lambda path: (len(path.parts), str(path)))


def verify_files(files, directories, gid):
    for path in (*directories, *files):
        info = path.lstat()
        mode = 0o750 if path in directories else 0o644 if path == UNIT_PATH else 0o640
        require((stat.S_ISDIR(info.st_mode) if path in directories else stat.S_ISREG(info.st_mode))
                and info.st_uid == 0 and info.st_gid == (0 if path == UNIT_PATH else gid)
                and stat.S_IMODE(info.st_mode) == mode,
                'Existing MTProto DD files have unexpected ownership or permissions')
    require(all(path.read_bytes() == value for path, value in files.items()),
            'A different MTProto DD installation already exists; refusing to overwrite it')
    for root in (RUNTIME, CONFIG_DIRECTORY):
        require(set(root.rglob('*')) == {path for path in (*directories, *files)
                                        if path != root and path.is_relative_to(root)},
                'Unexpected files occupy the private MTProto DD installation')


def verify_unit_definition():
    require(command('systemctl', 'show', '--property=FragmentPath', '--value', UNIT).strip()
            == str(UNIT_PATH).encode(), 'An unexpected unit occupies the MTProto DD service name')
    require(not command('systemctl', 'show', '--property=DropInPaths', '--value', UNIT).strip(),
            'Unexpected MTProto DD systemd drop-ins exist')


def install(archive, socks_wheel, secrets_file):
    settings, key = endpoint_settings(), read_secrets(secrets_file)
    files = read_assets(archive, socks_wheel)
    files.update({CONFIG: config_text(key, settings).encode(), UNIT_PATH: unit_text().encode()})
    directories = directories_for(files)
    check_dependency()
    occupied = any(os.path.lexists(path) for path in (RUNTIME, CONFIG_DIRECTORY, UNIT_PATH))
    if occupied:
        require(all(os.path.lexists(path) for path in (*directories, *files)),
                'An incomplete or unrelated installation occupies the MTProto DD paths')
        _, gid = check_account()
        verify_files(files, directories, gid)
        verify_unit_definition()
        command('systemctl', 'is-active', '--quiet', UNIT)
        verify_listener(settings)
        return {'already_installed': True, 'unit': UNIT}
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The MTProto DD service name is already in use')
    pool_available(settings)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((settings.bind, settings.port))
    try:
        identity = check_account()
    except KeyError:
        require(not any(group.gr_name == NAME for group in grp.getgrall()),
                'An unrelated group occupies the MTProto DD service name')
        identity = None
    created, identities, account_created, start_attempted = [], {}, False, False

    def remember(path):
        info = path.lstat()
        identities[path] = (info.st_dev, info.st_ino)

    def unchanged_identity(path):
        info = path.lstat()
        return identities[path] == (info.st_dev, info.st_ino) and not stat.S_ISLNK(info.st_mode)

    try:
        if identity is None:
            command('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', NAME)
            account_created = True
            identity = check_account()
        _, gid = identity
        for directory in directories:
            directory.mkdir(mode=0o750)
            created.append(directory)
            remember(directory)
            os.chown(directory, 0, gid)
            directory.chmod(0o750)
        for path, value in files.items():
            write_new(path, value, 0o644 if path == UNIT_PATH else 0o640, 0 if path == UNIT_PATH else gid)
            created.append(path)
            remember(path)
        command('systemd-analyze', 'verify', str(UNIT_PATH))
        command('systemctl', 'daemon-reload')
        verify_unit_definition()
        start_attempted = True
        command('systemctl', 'enable', '--now', UNIT)
        verify_listener(settings)
    except BaseException:
        own_unit = (UNIT_PATH in created and UNIT_PATH.is_file() and unchanged_identity(UNIT_PATH)
                    and UNIT_PATH.read_bytes() == files[UNIT_PATH])
        require(not start_attempted or own_unit,
                'The new MTProto DD unit changed; preserving installation files for inspection')
        if start_attempted:
            try:
                command('systemctl', 'disable', '--now', UNIT)
            except RuntimeError:
                raise RuntimeError('Could not stop the new MTProto DD unit; private files were preserved') from None
        # Validate every file before removing any. Do not remove another installer's replacement.
        require(all(unchanged_identity(path) and (path not in files or
                    (path.is_file() and path.read_bytes() == files[path])) for path in created),
                'An MTProto DD file changed; preserving installation files for inspection')
        for path in reversed(created):
            if path in files:
                path.unlink()
            else:
                path.rmdir()
        if own_unit:
            command('systemctl', 'daemon-reload')
        if account_created:
            require(check_account() == identity, 'The new MTProto DD account changed; preserving it')
            command('userdel', NAME)
        raise
    return {'installed': True, 'unit': UNIT, 'config': str(CONFIG),
            'source_commit': SOURCE_COMMIT, 'secure_only': True, 'existing_services_restarted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install'])
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--socks-wheel', type=Path, required=True)
    parser.add_argument('--secrets-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run this installer as root on the entry server')
        print(json.dumps(install(args.archive, args.socks_wheel, args.secrets_file)))
    except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile, SyntaxError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'install-mtproto-dd: ' + detail + '\n')


if __name__ == '__main__':
    main()
