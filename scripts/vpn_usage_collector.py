#!/usr/bin/env python3
"""Export persisted x-ui quota-period bytes without exposing subscription secrets."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time


DATABASE = Path('/etc/x-ui/x-ui.db')
DEVICES = Path('/etc/vpn-usage/devices.json')
OUTPUT = Path('/var/lib/vpn-node/textfile/vpn-usage.prom')
MAX_CLIENTS = 4096
MAX_MAPPING_BYTES = 1024 * 1024
MAX_SQLITE_ID = 2**63 - 1
ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', re.ASCII)
CLIENT_ID = re.compile(r'[1-9][0-9]{0,18}', re.ASCII)
DEFAULT_ALIAS = re.compile(r'sub-([1-9][0-9]*)', re.ASCII)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate key in device mapping')
        result[key] = value
    return result


def read_mapping(path):
    """Load opt-in public-safe aliases; do not register a device or consume a slot."""
    if path is None:
        return {}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o440, 0o600, 0o640):
            raise ValueError('Device mapping must be a private regular file (0600 or 0640)')
        data = stream.read(MAX_MAPPING_BYTES + 1)
    if len(data) > MAX_MAPPING_BYTES:
        raise ValueError('Device mapping is too large')
    raw = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(raw, dict) or len(raw) > MAX_CLIENTS:
        raise ValueError('Invalid device mapping size or type')
    seen = set()
    parsed = {}
    for key, value in raw.items():
        if not CLIENT_ID.fullmatch(key) or int(key) > MAX_SQLITE_ID:
            raise ValueError('Invalid numeric client key in device mapping')
        if not isinstance(value, dict) or set(value) != {'subscription', 'device'}:
            raise ValueError('Each device mapping entry requires subscription and device aliases')
        subscription, device = value['subscription'], value['device']
        if (not isinstance(subscription, str) or not ALIAS.fullmatch(subscription)
                or not isinstance(device, str) or (device and not ALIAS.fullmatch(device))):
            raise ValueError('Invalid subscription or device alias')
        reserved = DEFAULT_ALIAS.fullmatch(subscription)
        if reserved and reserved[1] != key:
            raise ValueError('Automatic subscription aliases are reserved for their own client')
        pair = (subscription, device)
        if pair in seen:
            raise ValueError('Duplicate subscription and device alias pair')
        seen.add(pair)
        parsed[int(key)] = pair
    return parsed


def reject_credential_labels(connection, labels):
    """Reject accidental credential-as-alias without returning any credential value."""
    available = {column[1] for column in connection.execute('PRAGMA table_info(clients)')}
    fields = [name for name in ('sub_id', 'uuid', 'email', 'password', 'auth', 'secret',
                                'wg_private_key', 'wg_pre_shared_key') if name in available]
    labels = sorted(set(labels) - {''})
    if not fields or not labels:
        return
    predicate = ' OR '.join(f'c.{field} COLLATE BINARY IN (SELECT value FROM aliases)' for field in fields)
    for offset in range(0, len(labels), 200):
        chunk = labels[offset:offset+200]
        places = ', '.join('(?)' for _ in chunk)
        query = (f'WITH aliases(value) AS (VALUES {places}) '
                 f'SELECT 1 FROM clients c WHERE ({predicate}) LIMIT 1')
        if connection.execute(query, chunk).fetchone():
            raise ValueError('A label matches a private x-ui identity or credential')


def read_usage(database, aliases):
    uri = database.resolve(strict=True).as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=3)) as connection:
        connection.execute('PRAGMA query_only = ON')
        connection.execute('BEGIN')
        # The accounting identity is the unique email, not every inbound membership.
        # There is no cumulative lifetime or HWID counter to add to this quota-period usage.
        data = connection.execute('''
            SELECT c.id, t.id IS NOT NULL, t.up, t.down
            FROM clients AS c
            LEFT JOIN client_traffics AS t ON t.email = c.email
            ORDER BY c.id LIMIT ?
        ''', (MAX_CLIENTS + 1,)).fetchall()
        if len(data) > MAX_CLIENTS:
            raise ValueError('Too many x-ui clients for one usage collector')
        rows = []
        identities = set()
        for client_id, has_traffic, up, down in data:
            if not isinstance(client_id, int) or not 0 < client_id <= MAX_SQLITE_ID:
                raise ValueError('Unexpected x-ui client identity schema')
            pair = aliases.get(client_id, (f'sub-{client_id}', ''))
            if pair in identities:
                raise ValueError('Duplicate accounting identity or Prometheus label pair')
            identities.add(pair)
            if has_traffic and any(not isinstance(v, int) or v < 0 for v in (up, down)):
                raise ValueError('Unexpected persisted x-ui traffic counter')
            rows.append((pair, (up, down) if has_traffic else None))
        reject_credential_labels(connection, (v for pair in identities for v in pair))
        return rows


def render(rows, now):
    traffic = 'vpn_usage_traffic_bytes_total'
    identity = 'vpn_usage_identity_info'
    stamp = 'vpn_usage_last_success_timestamp_seconds'
    lines = [f'# HELP {traffic} Persisted x-ui traffic bytes since the last quota reset.',
             f'# TYPE {traffic} counter']
    accounts = []
    for (subscription, device), counters in rows:
        # Aliases are constrained to ASCII label-safe characters above.
        labels = f'subscription="{subscription}",device="{device}"'
        accounts.append(f'{identity}{{{labels}}} 1')
        if counters is not None:
            for direction, value in zip(('upload', 'download'), counters):
                lines.append(f'{traffic}{{{labels},direction="{direction}"}} {value}')
    lines.extend([f'# HELP {identity} x-ui accounting identity grouped by configured aliases.',
                  f'# TYPE {identity} gauge', *accounts,
                  f'# HELP {stamp} Unix timestamp of the last successful usage collection.',
                  f'# TYPE {stamp} gauge', f'{stamp} {int(now)}'])
    return '\n'.join(lines) + '\n'


def replace_output(path, contents):
    # Same-directory rename: node_exporter sees only a fully rendered snapshot.
    with tempfile.NamedTemporaryFile(mode='w', encoding='ascii', dir=path.parent,
                                     prefix='.' + path.name + '.', suffix='.tmp', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def collect(database=DATABASE, devices=DEVICES, output=OUTPUT):
    rows = read_usage(database, read_mapping(devices))
    replace_output(output, render(rows, time.time()))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', '--db', type=Path, default=DATABASE)
    parser.add_argument('--devices', type=Path, default=DEVICES)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    try:
        collect(args.database, args.devices, args.output)
    except (OSError, ValueError, sqlite3.Error) as error:
        # Avoid dumping parser messages, filenames, or possible private values into journald.
        print('VPN usage collection failed: ' + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
