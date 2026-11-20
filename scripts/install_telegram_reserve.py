#!/usr/bin/env python3
"""Install three fresh-credential, loopback-only Telegram backends on the reserve host."""
import argparse
from dataclasses import dataclass
import grp
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import tarfile
import time

import install_mtproto as ee
import install_mtproto_dd as dd
from vpn_env import env, port


NAME = 'vpn-telegram-reserve'
ROLES = ('socks', 'dd', 'ee')
UNITS = {role: NAME + '-' + role + '.service' for role in ROLES}
RUNTIME = Path('/opt') / NAME
PRIVATE = Path('/etc') / NAME
SYSTEMD = Path('/etc/systemd/system')
SING_VERSION = '1.14.3'
SING_ARCHIVE_NAME = 'sing-box-' + SING_VERSION + '-linux-amd64.tar.gz'
SING_SHA256 = 'e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee'


def require(value, message):
    if not value:
        raise RuntimeError(message)


@dataclass(frozen=True)
class Endpoints:
    loopback: str
    public: str
    socks: int
    dd: int
    ee: int


def endpoints():
    value = Endpoints(env('VPN_LOOPBACK_IP'), env('VPN_NL_ADDRESS'),
                      port('VPN_NL_TELEGRAM_SOCKS_PORT'), port('VPN_NL_MTPROTO_DD_PORT'),
                      port('VPN_NL_MTPROTO_EE_PORT'))
    require(ipaddress.IPv4Address(value.loopback).is_loopback,
            'Reserve backends must bind an IPv4 loopback address')
    require(ipaddress.IPv4Address(value.public).is_global, 'Expected the reserve public IPv4 address')
    require(len({value.socks, value.dd, value.ee}) == len(ROLES)
            and all(1024 <= number <= 65535 for number in (value.socks, value.dd, value.ee)),
            'Reserve backends require distinct unprivileged ports')
    return value


def read_credentials(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
            'Reserve credentials must be a private regular JSON file')
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and value.get('scope') == 'netherlands-reserve-fresh',
            'Expected credentials generated specifically for the reserve host')
    require(isinstance(value.get('username'), str)
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value['username'])
            and isinstance(value.get('password'), str)
            and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value['password']),
            'Invalid reserve SOCKS credentials')
    keys = [value.get(name) for name in ('dd_key', 'ee_key')]
    require(all(isinstance(key, str) and re.fullmatch(r'[0-9a-f]{32}', key)
                and len(set(bytes.fromhex(key))) > 1 for key in keys)
            and len(set(keys)) == len(keys), 'Reserve DD and EE keys must be independent')
    domain = value.get('domain')
    require(isinstance(domain, str) and len(domain) <= 253
            and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                             r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain),
            'Invalid reserve cover domain')
    return value


def socks_config(value, settings):
    return {'log': {'disabled': True},
            'inbounds': [{'type': 'socks', 'tag': 'reserve-socks', 'listen': settings.loopback,
                          'listen_port': settings.socks,
                          'users': [{'username': value['username'], 'password': value['password']}]}],
            'outbounds': [{'type': 'direct', 'tag': 'reserve-direct'}],
            'route': {'rules': [{'ip_is_private': True, 'action': 'reject'},
                                {'ip_cidr': [settings.public + '/32'], 'action': 'reject'}],
                      'final': 'reserve-direct'}}


def dd_config(value, settings):
    source = dd.config_text(value['dd_key'],
                            dd.Endpoints(settings.loopback, settings.loopback, settings.public,
                                         settings.dd, settings.socks))
    options = {}
    exec(compile(source, '<reserve DD configuration>', 'exec'), {}, options)
    options.update(SOCKS5_HOST=None, SOCKS5_PORT=None)
    return ''.join(name + ' = ' + repr(item) + '\n' for name, item in options.items())


def ee_config(value, settings):
    secret = 'ee' + value['ee_key'] + value['domain'].encode('ascii').hex()
    return (f'debug = false\nsecret = {json.dumps(secret)}\n'
            f'bind-to = "{settings.loopback}:{settings.ee}"\n'
            f'public-ipv4 = "{settings.public}"\nprefer-ip = "only-ipv4"\n'
            'concurrency = 128\nauto-update = false\n'
            '[network]\ndns = ""\nproxies = []\n'
            '[network.timeout]\ntcp = "5s"\nhttp = "10s"\nidle = "5m"\nhandshake = "10s"\n'
            '[defense.anti-replay]\nenabled = true\nmax-size = "1mib"\n'
            '[defense.blocklist]\nenabled = false\n')


def unit_text(role):
    require(role in ROLES, 'Unknown reserve service role')
    commands = {'socks': f'{RUNTIME}/sing-box run -c {PRIVATE}/socks.json',
                'ee': f'{RUNTIME}/mtg run {PRIVATE}/ee.toml',
                'dd': f'/usr/bin/python3 -B {RUNTIME}/dd/vendor/source/mtprotoproxy.py {PRIVATE}/dd.py'}
    extra = (f'WorkingDirectory={RUNTIME}/dd/vendor/source\nEnvironment=PYTHONPATH={RUNTIME}/dd/vendor/pysocks\n'
             'Environment=PYTHONDONTWRITEBYTECODE=1\n') if role == 'dd' else ''
    families = 'AF_INET AF_INET6 AF_UNIX AF_NETLINK' if role == 'socks' else 'AF_INET AF_UNIX'
    return f'''[Unit]
Description=Independent reserve Telegram {role} proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={NAME}
Group={NAME}
ExecStart={commands[role]}
{extra}StandardInput=null
StandardOutput=null
StandardError=null
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
Environment=GOMAXPROCS=1
Environment=GOMEMLIMIT=64MiB
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
RestrictAddressFamilies={families}
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
'''


def read_sing_binary(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size < 64 * 1024 * 1024,
            'Expected the pinned sing-box archive')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == SING_SHA256,
            'Reserve SOCKS release SHA256 does not match its pin')
    with tarfile.open(path, 'r:gz') as archive:
        member = archive.getmember('sing-box-' + SING_VERSION + '-linux-amd64/sing-box')
        require(member.isfile() and 0 < member.size < 128 * 1024 * 1024,
                'Unsafe reserve SOCKS executable member')
        binary = archive.extractfile(member).read()
    require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\x3e\x00',
            'Reserve SOCKS executable must be Linux amd64')
    return binary


def payload(sing_archive, ee_archive, dd_archive, socks_wheel, credentials, settings):
    files = {RUNTIME / 'sing-box': read_sing_binary(sing_archive),
             RUNTIME / 'mtg': ee.read_binary(ee_archive),
             PRIVATE / 'socks.json': (json.dumps(socks_config(credentials, settings), indent=2) + '\n').encode(),
             PRIVATE / 'dd.py': dd_config(credentials, settings).encode(),
             PRIVATE / 'ee.toml': ee_config(credentials, settings).encode()}
    for path, value in dd.read_assets(dd_archive, socks_wheel).items():
        files[RUNTIME / 'dd' / path.relative_to(dd.RUNTIME)] = value
    for role in ROLES:
        files[SYSTEMD / UNITS[role]] = unit_text(role).encode()
    return files


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=40)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Reserve installation command timed out') from None
    require(result.returncode == 0, 'Reserve installation command failed: ' + str(args[0]))
    return result.stdout


def check_account():
    account, group = pwd.getpwnam(NAME), grp.getgrnam(NAME)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0
            and account.pw_dir == '/nonexistent' and account.pw_shell.endswith('/nologin'),
            'Unexpected reserve service account')
    return account.pw_uid, group.gr_gid


def layout(files):
    directories = {RUNTIME, PRIVATE}
    for path in files:
        if path.is_relative_to(RUNTIME):
            parent = path.parent
            while parent != RUNTIME:
                directories.add(parent)
                parent = parent.parent
    return sorted(directories, key=lambda path: (len(path.parts), str(path)))


def mode_for(path, directories):
    return 0o750 if path in directories else 0o755 if path in (RUNTIME / 'sing-box', RUNTIME / 'mtg') else 0o644 if path.parent == SYSTEMD else 0o640


def verify_files(files, directories, gid):
    for path in (*directories, *files):
        info = path.lstat()
        require((stat.S_ISDIR(info.st_mode) if path in directories else stat.S_ISREG(info.st_mode))
                and info.st_uid == 0 and info.st_gid == (0 if path.parent == SYSTEMD else gid)
                and stat.S_IMODE(info.st_mode) == mode_for(path, directories),
                'Reserve installation file ownership or mode differs')
    require(all(path.read_bytes() == data for path, data in files.items()),
            'Different reserve files already exist; refusing overwrite')
    for root in (RUNTIME, PRIVATE):
        require(set(root.rglob('*')) == {path for path in (*directories, *files)
                                        if path != root and path.is_relative_to(root)},
                'Unexpected files exist inside reserve installation')


def verify_units(settings):
    for role, number in (('socks', settings.socks), ('dd', settings.dd), ('ee', settings.ee)):
        unit = UNITS[role]
        require(command('systemctl', 'show', '--property=FragmentPath', '--value', unit).strip()
                == str(SYSTEMD / unit).encode(), 'Unexpected reserve unit definition')
        require(not command('systemctl', 'show', '--property=DropInPaths', '--value', unit).strip(),
                'Unexpected reserve unit drop-ins')
        deadline = time.monotonic() + 35
        last_failure = 'No listener readiness result'
        while True:
            try:
                command('systemctl', 'is-active', '--quiet', unit)
                pid = command('systemctl', 'show', '--property=MainPID', '--value', unit).strip()
                require(pid.isdigit() and int(pid) > 0, 'The reserve service has no running process')
                sockets = {os.readlink(path) for path in (Path('/proc') / pid.decode() / 'fd').iterdir()}
                expected_bind = socket.inet_aton(settings.loopback)[::-1].hex().upper()
                require(any(fields[3] == '0A' and fields[1] == expected_bind + ':' + format(number, '04X')
                            and 'socket:[' + fields[9] + ']' in sockets
                            for fields in (line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:])),
                        'The reserve listener is not owned by its service process')
                with socket.create_connection((settings.loopback, number), timeout=.5):
                    break
            except (OSError, RuntimeError) as error:
                last_failure = str(error) if isinstance(error, RuntimeError) else type(error).__name__
                require(time.monotonic() < deadline, 'Reserve ' + role + ' did not start: ' + last_failure)
                time.sleep(.2)


def install(args):
    require(os.geteuid() == 0, 'Run reserve installation as root on the reserve host')
    settings, credentials = endpoints(), read_credentials(args.credentials)
    files = payload(args.sing_archive, args.ee_archive, args.dd_archive,
                    args.socks_wheel, credentials, settings)
    directories = layout(files)
    dd.check_dependency()
    if any(os.path.lexists(path) for path in (RUNTIME, PRIVATE, *(SYSTEMD / name for name in UNITS.values()))):
        _, gid = check_account()
        verify_files(files, directories, gid)
        verify_units(settings)
        return {'already_installed': True, 'direct_exit': True, 'loopback_only': True}
    for unit in UNITS.values():
        require(command('systemctl', 'show', '--property=LoadState', '--value', unit).strip() == b'not-found',
                'A reserve service name is already occupied')
    for number in (settings.socks, settings.dd, settings.ee):
        with socket.socket() as listener:
            listener.bind((settings.loopback, number))
    try:
        identity = check_account()
    except KeyError:
        require(not any(group.gr_name == NAME for group in grp.getgrall()), 'Reserve group already exists')
        identity = None
    created, identities, started = [], {}, []
    account_created = False
    try:
        if identity is None:
            command('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', NAME)
            account_created = True
            identity = check_account()
        _, gid = identity
        for path in directories:
            path.mkdir(mode=0o750)
            created.append(path)
            os.chown(path, 0, gid)
            path.chmod(0o750)
            info = path.lstat()
            identities[path] = (info.st_dev, info.st_ino)
        for path, data in files.items():
            ee.write_new(path, data, mode_for(path, directories), 0 if path.parent == SYSTEMD else gid)
            created.append(path)
            info = path.lstat()
            identities[path] = (info.st_dev, info.st_ino)
        command(str(RUNTIME / 'sing-box'), 'check', '-c', str(PRIVATE / 'socks.json'))
        command('systemd-analyze', 'verify', *(str(SYSTEMD / unit) for unit in UNITS.values()))
        command('systemctl', 'daemon-reload')
        for unit in UNITS.values():
            started.append(unit)
            command('systemctl', 'enable', '--now', unit)
        verify_units(settings)
    except BaseException:
        # Check the entire new namespace before changing or removing any of it.
        require(all((info := path.lstat()) and not stat.S_ISLNK(info.st_mode)
                    and (info.st_dev, info.st_ino) == identities[path]
                    and (path not in files or path.read_bytes() == files[path]) for path in created),
                'Reserve files changed; preserving them for inspection')
        for unit in reversed(started):
            command('systemctl', 'disable', '--now', unit)
        for path in reversed(created):
            path.unlink() if path in files else path.rmdir()
        if any(path.parent == SYSTEMD for path in created):
            command('systemctl', 'daemon-reload')
        if account_created:
            require(check_account() == identity, 'Reserve account changed; preserving it')
            command('userdel', NAME)
        raise
    return {'installed': True, 'units': list(UNITS.values()), 'direct_exit': True,
            'loopback_only': True, 'existing_services_restarted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-archive', type=Path, required=True)
    parser.add_argument('--ee-archive', type=Path, required=True)
    parser.add_argument('--dd-archive', type=Path, required=True)
    parser.add_argument('--socks-wheel', type=Path, required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args), sort_keys=True))
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError):
        raise SystemExit('Reserve installation refused or failed; inspect private files without exposing credentials') from None


if __name__ == '__main__':
    main()
