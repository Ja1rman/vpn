#!/usr/bin/env python3
"""Publish native x-ui TLS subscription hosts without changing VPN authorization."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import argparse
from contextlib import closing
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import time
import uuid


DATABASE = Path('/etc/x-ui/x-ui.db')
BACKUPS = Path('/var/backups/vpn-infra')
PORTS = {env_port('VPN_VLESS_AUTH_PORT'): env_port('VPN_STANDARD_TLS_PORT'), env_port('VPN_PRIMARY_VLESS_PORT'): env_port('VPN_PRIMARY_TLS_PORT'), env_port('VPN_NL_RELAY_VLESS_PORT'): env_port('VPN_NL_RELAY_TLS_PORT'), env_port('VPN_THIRD_VLESS_PORT'): env_port('VPN_THIRD_TLS_PORT')}
MARKER = 'vpn-infra-xray-tls'
ARRAY_FIELDS = ('tags', 'alpn', 'pinned_peer_cert_sha256', 'exclude_from_sub_types', 'node_guids')
EMPTY_FIELDS = ('server_description', 'host_header', 'path', 'fingerprint', 'verify_peer_cert_by_name',
                'ech_config_list', 'mux_params', 'sockopt_params', 'final_mask', 'vless_route',
                'mihomo_ip_version', 'cipher_suites')
FALSE_FIELDS = ('is_disabled', 'is_hidden', 'override_sni_from_address', 'keep_sni_blank',
                'allow_insecure', 'mihomo_x25519', 'shuffle_host')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def connect(database, writable=False):
    path = database.resolve(strict=True)
    conn = sqlite3.connect(path.as_uri() + ('?mode=rw' if writable else '?mode=ro'),
                           uri=True, timeout=5, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if not writable:
        conn.execute('PRAGMA query_only = ON')
    return conn


def identity(database):
    info = database.stat()
    return {'database': str(database.resolve()), 'device': info.st_dev, 'inode': info.st_ino}


def desired_host(inbound_id, target_port, address):
    result = {field: '' for field in EMPTY_FIELDS}
    result.update({field: '[]' for field in ARRAY_FIELDS})
    result.update({field: 0 for field in FALSE_FIELDS})
    result.update(inbound_id=inbound_id, sort_order=0, remark=f'VLESS TLS {target_port}',
                  tags=json.dumps([MARKER]), address=str(address), port=target_port,
                  security='tls', sni=str(address))
    return result


def publication_plan(conn, address):
    required = set(desired_host(1, env_port('VPN_STANDARD_TLS_PORT'), address)) | {'id', 'group_id', 'created_at', 'updated_at'}
    columns = {row['name'] for row in conn.execute('PRAGMA table_info(hosts)')}
    require(required <= columns, 'Native x-ui hosts schema is not supported')
    additions, existing = [], 0
    for source, target in PORTS.items():
        inbounds = conn.execute('SELECT id,protocol,enable,exclude_from_sub,stream_settings '
                                'FROM inbounds WHERE port=?', (source,)).fetchall()
        require(len(inbounds) == 1, 'Expected one plain VLESS inbound for each source port')
        inbound = inbounds[0]
        require(inbound['protocol'] == 'vless' and inbound['enable'] == 1 and not inbound['exclude_from_sub'],
                'A source inbound is not an enabled published VLESS inbound')
        stream = json.loads(inbound['stream_settings'])
        require(stream.get('network') in ('tcp', 'raw') and stream.get('security', 'none') in ('', 'none'),
                'A source inbound is not plain VLESS over TCP')
        require(not stream.get('externalProxy'), 'An existing externalProxy subscription override conflicts')
        expected = desired_host(inbound['id'], target, address)
        rows = conn.execute('SELECT * FROM hosts WHERE inbound_id=?', (inbound['id'],)).fetchall()
        if rows:
            require(len(rows) == 1 and all(rows[0][key] == value for key, value in expected.items()),
                    'An existing native host was not created by this publication or has been edited')
            existing += 1
        else:
            additions.append(expected)
    return additions, {'native_tls_hosts_to_insert': len(additions),
                       'native_tls_hosts_already_present': existing,
                       'source_ports': list(PORTS), 'tls_ports': list(PORTS.values())}


def verify_tls_listeners(address):
    context = ssl.create_default_context()
    for port in PORTS.values():
        try:
            with socket.create_connection((env_value('VPN_LOOPBACK_IP'), port), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=str(address)):
                    pass
        except (OSError, ssl.SSLError):
            raise RuntimeError('A TLS subscription endpoint is unavailable or untrusted') from None


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def apply(database, address, backup_root):
    verify_tls_listeners(address)
    with closing(connect(database, writable=True)) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            additions, report = publication_plan(conn, address)
            if not additions:
                conn.execute('COMMIT')
                return {**report, 'inserted': 0, 'backup': None}
            backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            backup = backup_root / ('xray-subscription-hosts-' +
                                    datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
            backup.mkdir(mode=0o700)
            info = identity(database)
            private_json(backup / 'before.json', {**info, 'affected_inbounds': [x['inbound_id'] for x in additions]})
            inserted, now = [], int(time.time()*1000)
            for values in additions:
                values = dict(values, group_id=str(uuid.uuid4()), created_at=now, updated_at=now)
                keys = list(values)
                cursor = conn.execute('INSERT INTO hosts (' + ','.join(keys) + ') VALUES (' +
                                      ','.join('?' for _ in keys) + ')', [values[key] for key in keys])
                row = conn.execute('SELECT * FROM hosts WHERE id=?', (cursor.lastrowid,)).fetchone()
                inserted.append(dict(row))
            private_json(backup / 'inserted.json', {**info, 'address': str(address), 'rows': inserted})
            directory = os.open(backup, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            conn.execute('COMMIT')
            return {**report, 'inserted': len(inserted), 'backup': str(backup)}
        except BaseException:
            if conn.in_transaction:
                conn.execute('ROLLBACK')
            raise


def rollback(database, backup):
    require(not backup.is_symlink() and backup.is_dir(), 'Expected a private backup directory')
    path = backup / 'inserted.json'
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'Expected a private owned recovery manifest')
    saved = json.loads(path.read_text())
    require(all(saved.get(key) == value for key, value in identity(database).items()),
            'Recovery manifest belongs to another database file')
    address = ipaddress.IPv4Address(saved.get('address'))
    rows = saved.get('rows')
    require(isinstance(rows, list) and 0 < len(rows) <= len(PORTS), 'Invalid host recovery rows')
    ids = [row.get('id') for row in rows]
    require(all(type(value) is int and value > 0 for value in ids) and len(set(ids)) == len(ids),
            'Invalid host recovery identities')
    for row in rows:
        require(row.get('port') in PORTS.values(), 'Unknown TLS recovery endpoint')
        expected = desired_host(row.get('inbound_id'), row['port'], address)
        require(all(row.get(key) == value for key, value in expected.items()), 'Recovery row ownership mismatch')
    with closing(connect(database, writable=True)) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            present, missing = [], 0
            for old in rows:
                current = conn.execute('SELECT * FROM hosts WHERE id=?', (old['id'],)).fetchone()
                if current is None:
                    missing += 1
                    continue
                require(dict(current) == old, 'A native host was edited; refusing the entire rollback')
                present.append(old['id'])
            for host_id in present:
                conn.execute('DELETE FROM hosts WHERE id=?', (host_id,))
            conn.execute('COMMIT')
            return {'deleted': len(present), 'already_absent': missing, 'backup': str(backup)}
        except BaseException:
            if conn.in_transaction:
                conn.execute('ROLLBACK')
            raise


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('plan', 'apply', 'rollback'):
        child = commands.add_parser(action)
        child.add_argument('--database', type=Path, default=DATABASE)
        if action == 'rollback':
            child.add_argument('backup', type=Path)
        else:
            child.add_argument('--address', type=ipaddress.IPv4Address, default=ipaddress.IPv4Address(env_value('VPN_ENTRY_ADDRESS')))
            if action == 'apply':
                child.add_argument('--backup-root', type=Path, default=BACKUPS)
    args = parser.parse_args()
    if args.action == 'plan':
        with closing(connect(args.database)) as conn:
            _, result = publication_plan(conn, args.address)
    elif args.action == 'apply':
        result = apply(args.database, args.address, args.backup_root)
    else:
        result = rollback(args.database, args.backup)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
