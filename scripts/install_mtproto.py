#!/usr/bin/env python3
"""Install an independent MTProto frontend using the existing VPN Auto SOCKS pool."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import time


NAME = 'vpn-mtproto'
UNIT = NAME + '.service'
VERSION = '2.3.0'
ARCHIVE_NAME = 'mtg-2.3.0-linux-amd64.tar.gz'
ARCHIVE_SHA256 = '11c038ea5eeebd5d49148048975c24f7b0c4fa4c1cf4f15a2410203e2da01812'
ADDRESS = env_value('VPN_ENTRY_ADDRESS')
PORT = env_port('VPN_MTPROTO_PORT')
POOL_PORT = env_port('VPN_FAILOVER_SOCKS_PORT')
CONFIG_DIRECTORY = Path('/etc') / NAME
RUNTIME = Path('/opt') / NAME
CONFIG = CONFIG_DIRECTORY / 'config.toml'
BINARY = RUNTIME / 'mtg'
UNIT_PATH = Path('/etc/systemd/system') / UNIT


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('MTProto installation command timed out') from None
    require(result.returncode == 0, 'MTProto installation command failed: ' + args[0])
    return result.stdout


def read_secrets(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
            'The MTProto secrets file must be a private regular file')
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and {'secret', 'domain'} <= set(value),
            'The MTProto secrets JSON must contain secret and domain')
    secret, domain = value['secret'], value['domain']
    require(isinstance(domain, str) and len(domain) <= 253
            and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                             r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain),
            'Invalid MTProto FakeTLS domain')
    require(isinstance(secret, str) and re.fullmatch(r'ee[0-9a-f]{32}(?:[0-9a-f]{2}){1,253}', secret),
            'The MTProto secret must use FakeTLS ee encoding')
    require(bytes.fromhex(secret[34:]) == domain.encode('ascii'),
            'The MTProto FakeTLS secret does not match its domain')
    return value


def read_binary(archive):
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size < 32 * 1024 * 1024,
            'Expected a regular pinned MTProto release archive')
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA256,
            'The MTProto release archive checksum does not match the pinned release')
    with tarfile.open(archive, 'r:gz') as source:
        members = [m for m in source if PurePosixPath(m.name).name == 'mtg']
        require(len(members) == 1, 'Expected one MTProto executable in the release archive')
        member = members[0]
        path = PurePosixPath(member.name)
        require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                and 0 < member.size < 64 * 1024 * 1024,
                'Unsafe MTProto executable archive member')
        with source.extractfile(member) as stream:
            binary = stream.read(64 * 1024 * 1024)
    require(len(binary) == member.size and binary[:6] == b'\x7fELF\x02\x01'
            and binary[18:20] == b'\x3e\x00', 'Expected the pinned Linux amd64 MTProto executable')
    return binary


def config_text(secrets):
    return env_expand(f'''debug = false\nsecret = {json.dumps(secrets['secret'])}\nbind-to = "${{VPN_BIND_IP}}:{PORT}"\npublic-ipv4 = "{ADDRESS}"\nprefer-ip = "only-ipv4"\nconcurrency = 128\nauto-update = false\n\n[network]\ndns = "https://${{VPN_DNS_ADDRESS}}/dns-query"\nproxies = ["socks5://${{VPN_LOOPBACK_IP}}:{POOL_PORT}"]\n\n[network.timeout]\ntcp = "5s"\nhttp = "10s"\nidle = "5m"\nhandshake = "10s"\n\n[defense.anti-replay]\nenabled = true\nmax-size = "1mib"\n\n[defense.blocklist]\nenabled = false\n''')


def unit_text():
    return f'''[Unit]
Description=Telegram MTProto proxy through VPN Auto
Wants=network-online.target
After=network-online.target vpn-failover-pool.service

[Service]
Type=simple
User={NAME}
Group={NAME}
ExecStart={BINARY} run {CONFIG}
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
'''


def check_account():
    account = pwd.getpwnam(NAME)
    group = grp.getgrnam(NAME)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0
            and account.pw_dir == '/nonexistent' and account.pw_shell.endswith('/nologin'),
            'The MTProto service name is occupied by an unexpected account')
    return account.pw_uid, group.gr_gid


def pool_available():
    with socket.create_connection((env_value('VPN_LOOPBACK_IP'), POOL_PORT), timeout=3) as connection:
        connection.sendall(b'\x05\x01\x00')
        require(connection.recv(2) == b'\x05\x00', 'The existing VPN Auto SOCKS pool did not answer')


def check_listener():
    for _ in range(30):
        try:
            with socket.create_connection((env_value('VPN_LOOPBACK_IP'), PORT), timeout=.5):
                return
        except OSError:
            time.sleep(.2)
    raise RuntimeError('The MTProto frontend did not open its listener')


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


def verify_existing(files):
    _, gid = check_account()
    expected = {RUNTIME: (0, 0o755), CONFIG_DIRECTORY: (gid, 0o750),
                BINARY: (0, 0o755), CONFIG: (gid, 0o640), UNIT_PATH: (0, 0o644)}
    for path, (group, mode) in expected.items():
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == 0 and info.st_gid == group
                and stat.S_IMODE(info.st_mode) == mode,
                'Existing MTProto installation has unexpected ownership or permissions')
    require(all(path.is_file() and path.read_bytes() == data for path, data in files.items()),
            'A different MTProto installation already exists; inspect it before changing configuration')
    command('systemctl', 'is-active', '--quiet', UNIT)
    check_listener()


def install(archive, secrets_file):
    secrets = read_secrets(secrets_file)
    files = {BINARY: read_binary(archive), CONFIG: config_text(secrets).encode(), UNIT_PATH: unit_text().encode()}
    if any(os.path.lexists(path) for path in (RUNTIME, CONFIG_DIRECTORY, UNIT_PATH)):
        require(all(os.path.lexists(path) for path in (*files, RUNTIME, CONFIG_DIRECTORY)),
                'An incomplete or unrelated MTProto installation already occupies these paths')
        verify_existing(files)
        return {'already_installed': True, 'port': PORT, 'version': VERSION}
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The MTProto service name is already in use')
    pool_available()
    with socket.socket() as listener:
        listener.bind((env_value('VPN_BIND_IP'), PORT))
    created, account_created = [], False
    try:
        try:
            check_account()
        except KeyError:
            require(not any(g.gr_name == NAME for g in grp.getgrall()),
                    'An unrelated group occupies the MTProto service name')
            command('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', NAME)
            account_created = True
        _, gid = check_account()
        for directory, mode, group in ((RUNTIME, 0o755, 0), (CONFIG_DIRECTORY, 0o750, gid)):
            directory.mkdir(mode=mode)
            created.append(directory)
            os.chown(directory, 0, group)
            directory.chmod(mode)
        for path, data in files.items():
            write_new(path, data, 0o640 if path == CONFIG else 0o755 if path == BINARY else 0o644,
                      gid if path == CONFIG else 0)
            created.append(path)
        version = command(str(BINARY), '--version').decode()
        require(VERSION in version, 'The pinned MTProto executable reported an unexpected version')
        command('systemd-analyze', 'verify', str(UNIT_PATH))
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', UNIT)
        check_listener()
        command('systemctl', 'is-active', '--quiet', UNIT)
    except BaseException:
        if UNIT_PATH in created:
            command('systemctl', 'disable', '--now', UNIT)
        for path in reversed(created):
            shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True)
        if UNIT_PATH in created:
            command('systemctl', 'daemon-reload')
        if account_created:
            command('userdel', NAME)
        raise
    return {'installed': True, 'port': PORT, 'version': VERSION, 'config': str(CONFIG)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install'])
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--secrets-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run this installer as root on the entry server')
        print(json.dumps(install(args.archive, args.secrets_file)))
    except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'install-mtproto: ' + detail + '\n')


if __name__ == '__main__':
    main()
