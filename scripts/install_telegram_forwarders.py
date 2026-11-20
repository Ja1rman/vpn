#!/usr/bin/env python3
"""Add two fixed TCP access sockets without changing their existing VPN backends."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess


UNIT_DIR = Path('/etc/systemd/system')
BACKUPS = Path('/var/backups/vpn-infra')
NAMES = {'auto': 'vpn-auto-access', 'socks': 'vpn-socks-access'}
PROXY_PATHS = (Path('/lib/systemd/systemd-socket-proxyd'),
               Path('/usr/lib/systemd/systemd-socket-proxyd'))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@dataclass(frozen=True)
class Forwarder:
    name: str
    bind: str
    loopback: str
    public_port: int
    backend_port: int


def settings(component='all'):
    from vpn_env import env, port
    bind, loopback = env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP')
    require(not ipaddress.IPv4Address(bind).is_multicast, 'Expected a unicast TCP bind address')
    require(ipaddress.IPv4Address(loopback).is_loopback, 'The fixed TCP targets must use IPv4 loopback')
    variables = {'auto': ('VPN_AUTO_TLS_PUBLIC_PORT', 'VPN_AUTO_TLS_PORT'),
                 'socks': ('VPN_TELEGRAM_SOCKS_PUBLIC_PORT', 'VPN_TELEGRAM_SOCKS_PORT')}
    selected = variables if component == 'all' else {component: variables[component]}
    result = {role: Forwarder(NAMES[role], bind, loopback, port(public), port(backend))
              for role, (public, backend) in selected.items()}
    require(all(item.public_port >= 1024 for item in result.values()),
            'Use unprivileged public TCP ports for these additional listeners')
    require(len({value for item in result.values() for value in (item.public_port, item.backend_port)}) == 2*len(result),
            'Access and backend ports must be distinct')
    return result


def command(*args, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('A fixed TCP forwarder command timed out') from None
    require(result.returncode == 0, 'A fixed TCP forwarder command failed: ' + args[0])
    return result.stdout


def proxy_binary():
    for path in PROXY_PATHS:
        if not path.is_file():
            continue
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_mode & 0o111,
                'Expected the root-owned operating system socket proxy executable')
        return path
    raise RuntimeError('The operating system systemd-socket-proxyd executable is unavailable')


def unit_texts(item, binary):
    require(item.name in NAMES.values(), 'Unknown fixed TCP forwarder name')
    socket_unit = f'''[Unit]
Description=Additional fixed TCP access for {item.name}

[Socket]
ListenStream={item.bind}:{item.public_port}
Accept=no
NoDelay=true
Backlog=128

[Install]
WantedBy=sockets.target
'''
    service_unit = f'''[Unit]
Description=Unprivileged fixed TCP relay for {item.name}
After=network-online.target

[Service]
ExecStart={binary} --connections-max=128 --exit-idle-time=5min {item.loopback}:{item.backend_port}
DynamicUser=yes
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
MemoryMax=64M
CPUQuota=50%
TasksMax=16
LimitNOFILE=1024
TimeoutStopSec=10
UMask=0077
'''
    return {UNIT_DIR / (item.name + '.socket'): socket_unit.encode(),
            UNIT_DIR / (item.name + '.service'): service_unit.encode()}


def unit_record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
            stat.S_IMODE(info.st_mode) == 0o644, 'A fixed forwarder unit has unexpected ownership or mode')
    return {'name': path.name, 'device': info.st_dev, 'inode': info.st_ino,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def ensure_socket_active(name):
    state = command('systemctl', 'show', name + '.socket', '-p', 'SubState', '--value').strip()
    require(state == b'listening', 'A fixed TCP access socket is not listening')


def preflight(item, files):
    existing = [os.path.lexists(path) for path in files]
    for path in files:
        require(not os.path.lexists(Path(str(path) + '.d')), 'A fixed forwarder has owner-defined drop-ins')
    if any(existing):
        require(all(existing), 'A partial fixed forwarder installation already exists')
        for path, expected in files.items():
            unit_record(path)
            require(path.read_bytes() == expected,
                    'A different fixed forwarder installation already exists; leaving it unchanged')
        ensure_socket_active(item.name)
        return True
    for path in files:
        require(command('systemctl', 'show', path.name, '-p', 'LoadState', '--value').strip() == b'not-found',
                'A fixed TCP forwarder unit name is already in use')
    try:
        with socket.socket() as listener:
            listener.bind((item.bind, item.public_port))
        with socket.create_connection((item.loopback, item.backend_port), timeout=3):
            pass
    except OSError:
        raise RuntimeError('A new listener is occupied or its existing backend is unavailable') from None
    return False


def write_new(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def validate_records(records):
    allowed = {name + suffix for name in NAMES.values() for suffix in ('.socket', '.service')}
    require(isinstance(records, list) and 0 < len(records) <= len(allowed), 'Invalid forwarder recovery records')
    names = [row.get('name') for row in records]
    require(len(names) == len(set(names)) and all(name in allowed for name in names),
            'Invalid forwarder recovery unit names')
    for row in records:
        require(unit_record(UNIT_DIR / row['name']) == row,
                'A new forwarder unit was edited or replaced; refusing the entire rollback')


def remove_owned(records):
    # Validate every file before stopping or deleting any unit.
    validate_records(records)
    sockets = sorted(row['name'] for row in records if row['name'].endswith('.socket'))
    services = sorted(row['name'] for row in records if row['name'].endswith('.service'))
    if sockets:
        command('systemctl', 'disable', '--now', *sockets)
    if services:
        command('systemctl', 'stop', *services)
    for unit in sockets + services:
        state = command('systemctl', 'show', unit, '-p', 'ActiveState', '--value').strip()
        require(state in (b'inactive', b'failed'), 'A new forwarder did not stop; retaining its files')
    for row in records:
        path = UNIT_DIR / row['name']
        require(unit_record(path) == row, 'A forwarder unit changed during rollback')
        path.unlink()
    command('systemctl', 'daemon-reload')


def install(component='all', backup_root=BACKUPS):
    configured = settings(component)
    selected = list(configured.values()) if component == 'all' else [configured[component]]
    binary = proxy_binary()
    pending, existing = [], []
    for item in selected:
        files = unit_texts(item, binary)
        if preflight(item, files):
            existing.append(item.name)
        else:
            pending.append((item, files))
    if not pending:
        return {'installed': [], 'already_active': existing, 'backup': None}
    created, manifest = [], None
    try:
        for item, files in pending:
            for path, content in files.items():
                write_new(path, content, 0o644)
                created.append(unit_record(path))
        backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        backup = backup_root / ('telegram-forwarders-' +
                                datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(mode=0o700)
        manifest = backup / 'created.json'
        write_new(manifest, (json.dumps({'created': created}, indent=2) + '\n').encode(), 0o600)
        command('systemd-analyze', 'verify', *(str(UNIT_DIR / row['name']) for row in created))
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', *(item.name + '.socket' for item, _ in pending))
        for item, _ in pending:
            ensure_socket_active(item.name)
        return {'installed': [item.name for item, _ in pending], 'already_active': existing,
                'backup': str(manifest)}
    except BaseException:
        if created:
            remove_owned(created)
        raise


def rollback(manifest):
    info = manifest.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            'Expected a private root-owned forwarder recovery manifest')
    records = json.loads(manifest.read_text()).get('created')
    remove_owned(records)
    return {'removed': sorted({row['name'].rsplit('.', 1)[0] for row in records})}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    install_parser = actions.add_parser('install')
    install_parser.add_argument('--component', choices=('auto', 'socks', 'all'), default='all')
    install_parser.add_argument('--backup-root', type=Path, default=BACKUPS)
    actions.add_parser('rollback').add_argument('manifest', type=Path)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run the fixed TCP forwarder installer as root')
        result = install(args.component, args.backup_root) if args.action == 'install' else rollback(args.manifest)
        print(json.dumps(result))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'install-telegram-forwarders: ' + message + '\n')


if __name__ == '__main__':
    main()
