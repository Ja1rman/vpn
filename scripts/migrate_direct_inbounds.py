#!/usr/bin/env python3
"""Route the four legacy inputs through the pool; never restart a VPN process.

Run as root on entry. Only routing is hot-applied with Xray's RoutingService.
The template is persisted using a compare-and-swap SQLite transaction so no
panel reconcile (and its possible restart fallback) is triggered. x-ui reads
this setting from SQLite whenever it builds the desired configuration.
"""
import base64
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

from activate_balancer import probe, xray_pids
from panel import Panel
from verify_vpn import udp_dns

XRAY = '/usr/local/x-ui/bin/xray-linux-amd64'
CONFIG = Path('/usr/local/x-ui/bin/config.json')
DB = '/etc/x-ui/x-ui.db'
TARGETS = {'in-26279-tcp': ('http', 26279),
           'in-48607-tcp': ('http', 48607),
           'in-13298-tcp': ('mixed', 13298),
           'in-36307-udp': ('wireguard', 36307)}
POOL = 'vpn-egress-pool'


def add_routes(config):
    """Preserve every existing rule and reject conflicting target routes."""
    new = copy.deepcopy(config)
    out = next((o for o in config['outbounds'] if o.get('tag') == POOL), None)
    if out != {'tag': POOL, 'protocol': 'socks',
               'settings': {'address': '127.0.0.1', 'port': 11090}}:
        raise ValueError('Expected loopback pool outbound is missing or different')
    for tag in TARGETS:
        matches = [r for r in config['routing']['rules']
                   if tag in r.get('inboundTag', []) and r.get('enabled', True)]
        if matches:
            # Only the exact unconditional rule makes a repeated run a no-op.
            allowed = {'type', 'inboundTag', 'outboundTag', 'enabled'}
            if len(matches) != 1 or set(matches[0]) - allowed or \
                    matches[0].get('inboundTag') != [tag] or \
                    matches[0].get('outboundTag') != POOL:
                raise ValueError('Conflicting existing rule for ' + tag)
            continue
        new['routing']['rules'].append({'type': 'field', 'inboundTag': [tag],
                                        'outboundTag': POOL})
    return new


def normalized_routing(routing):
    new = copy.deepcopy(routing)
    new['rules'] = [r for r in new['rules'] if r.get('enabled', True)]
    for rule in new['rules']:
        rule.pop('enabled', None)
    return new


def template_raw():
    with sqlite3.connect('file:' + DB + '?mode=ro', uri=True) as db:
        return db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]


def save_template(expected, desired):
    with sqlite3.connect(DB, timeout=15) as db:
        updated = db.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig' AND value=?",
                             (desired, expected)).rowcount
        if updated != 1:
            raise RuntimeError('Template changed concurrently; refusing to overwrite it')


def config_without_routing(config):
    return {k: v for k, v in config.items() if k != 'routing'}


def save_runtime(expected, desired):
    """Atomically synchronize only generated routing, preserving all inputs."""
    if json.loads(CONFIG.read_text()) != expected:
        raise RuntimeError('Runtime changed concurrently; refusing to overwrite it')
    stat = CONFIG.stat()
    fd, name = tempfile.mkstemp(prefix='.vpn-routing-', dir=CONFIG.parent)
    try:
        os.fchmod(fd, stat.st_mode & 0o777)
        os.fchown(fd, stat.st_uid, stat.st_gid)
        with os.fdopen(fd, 'w') as output:
            json.dump(desired, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, CONFIG)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply_routing(path):
    result = subprocess.run([XRAY, 'api', 'adrules', '--server=127.0.0.1:62789', str(path)],
                            capture_output=True, text=True, timeout=15,
                            env=dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/x-ui/bin'))
    if result.returncode:
        raise RuntimeError('RoutingService rejected configuration: ' + result.stderr)


def rollback(folder, force=False):
    with (folder / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if ((folder / 'committed').exists() and not force) or (folder / 'rolled-back').exists():
            return
        old = json.loads((folder / 'runtime-before.json').read_text())
        new = json.loads((folder / 'runtime-after.json').read_text())
        old_raw = (folder / 'template-before.json').read_text()
        new_raw = (folder / 'template-after.json').read_text()
        current = json.loads(CONFIG.read_text())
        if config_without_routing(current) != config_without_routing(old) or \
                current['routing'] not in [old['routing'], new['routing']]:
            raise RuntimeError('Concurrent runtime change; manual route rollback required')
        raw = template_raw()
        if raw not in [old_raw, new_raw]:
            raise RuntimeError('Concurrent template change; manual route rollback required')
        apply_routing(folder / 'routing-before.json')
        if raw == new_raw:
            save_template(new_raw, old_raw)
        if current != old:
            save_runtime(current, old)
        if (folder / 'committed').exists():
            (folder / 'committed').rename(folder / 'committed-before-manual-rollback')
        (folder / 'rolled-back').write_text('Routing restored without restarting processes\n')


class Tunnel:
    """Hold an authenticated HTTP CONNECT connection across the routing swap."""
    def __init__(self, inbound):
        self.banner_received = False
        destination = '144.31.34.165:22'
        account = inbound['settings']['accounts'][0]
        auth = base64.b64encode((account['user'] + ':' + account['pass']).encode()).decode()
        sock = socket.create_connection(('127.0.0.1', inbound['port']), timeout=12)
        try:
            sock.sendall((f'CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n'
                          'Proxy-Authorization: Basic ' + auth + '\r\n\r\n').encode())
            header = b''
            while not header.endswith(b'\r\n\r\n') and len(header) < 16384:
                chunk = sock.recv(1)
                if not chunk:
                    raise RuntimeError('Proxy closed CONNECT')
                header += chunk
            if header.split(b'\r\n')[0].split()[1] != b'200':
                raise RuntimeError('Authenticated CONNECT failed')
            self.socket = sock
            self.reader = sock.makefile('rb')
        except BaseException:
            sock.close()
            raise

    def query(self):
        if not self.banner_received:
            banner = self.reader.readline(1024)
            if not banner.startswith(b'SSH-2.0-'):
                raise RuntimeError('SSH canary banner missing')
            self.banner_received = True
            return 'SSH banner received'
        # Finish version exchange on the SAME socket after the routing swap.
        # No SSH authentication is attempted; no account or service is changed.
        self.socket.sendall(b'SSH-2.0-vpn-route-canary\r\n')
        size = self.reader.read(4)
        if len(size) != 4:
            raise RuntimeError('Existing tunnel closed during routing swap')
        length = int.from_bytes(size, 'big')
        if not 16 <= length <= 65536:
            raise RuntimeError('Invalid SSH canary packet')
        packet = self.reader.read(length)
        if len(packet) != length or packet[1] != 20:  # SSH_MSG_KEXINIT
            raise RuntimeError('SSH key exchange response missing')
        return 'SSH key exchange received on original socket'

    def close(self):
        self.reader.close()
        self.socket.close()


def route_checks(panel):
    checks = []
    for tag in TARGETS:
        for network in ['tcp', 'udp']:
            result = panel.request('xray/routeTest', {'inboundTag': tag, 'ip': '1.1.1.1',
                                                     'port': 443, 'network': network})
            if not result.get('matched') or result.get('outboundTag') != POOL:
                raise RuntimeError('Live route test failed for ' + tag + '/' + network)
            checks.append(tag + '/' + network)
    return checks


def panel_template_check(panel, expected):
    obj = panel.request('xray/', {})
    if isinstance(obj, str):
        obj = json.loads(obj)
    saved = obj['xraySetting']
    if isinstance(saved, str):
        saved = json.loads(saved)
    if saved != expected:
        raise RuntimeError('Panel does not expose the persisted template')


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1] in {'watchdog', 'rollback'}:
        if sys.argv[1] == 'watchdog':
            time.sleep(180)
        rollback(Path(sys.argv[2]), force=sys.argv[1] == 'rollback')
        return
    old_raw = template_raw()
    old_template = json.loads(old_raw)
    old = json.loads(CONFIG.read_text())
    new_template = add_routes(old_template)
    new = add_routes(old)
    if normalized_routing(old_template['routing']) != old['routing']:
        raise RuntimeError('Template/runtime routing differ before migration')
    if new == old and new_template == old_template:
        panel = Panel()
        try:
            route_checks(panel)
            panel_template_check(panel, new_template)
        finally:
            panel.close()
        print('All four inputs already route through the pool; live routes verified; nothing changed')
        return
    for tag, (protocol, port) in TARGETS.items():
        inbound = next(i for i in old['inbounds'] if i['tag'] == tag)
        if (inbound['protocol'], inbound['port']) != (protocol, port):
            raise RuntimeError('Unexpected inbound identity for ' + tag)
    if config_without_routing(old) != config_without_routing(new):
        raise RuntimeError('Migration may only change routing')
    folder = Path('/var/backups/vpn-infra') / ('routes-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    folder.mkdir(parents=True, mode=0o700)
    new_raw = json.dumps(new_template)
    for name, content in [('template-before.json', old_raw), ('template-after.json', new_raw),
                          ('runtime-before.json', json.dumps(old)), ('runtime-after.json', json.dumps(new)),
                          ('routing-before.json', json.dumps({'routing': old['routing']})),
                          ('routing-after.json', json.dumps({'routing': new['routing']}))]:
        (folder / name).write_text(content)
    result = subprocess.run([XRAY, 'run', '-test', '-config', str(folder / 'runtime-after.json')],
                            capture_output=True, timeout=20,
                            env=dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/x-ui/bin'))
    if result.returncode:
        raise RuntimeError('Candidate failed Xray config validation')
    pids = xray_pids()
    expected = probe('socks5h://127.0.0.1:11090')
    panel = Panel()
    tunnels = {}
    before = {}
    try:
        for tag, (protocol, port) in TARGETS.items():
            if protocol != 'wireguard':
                tunnel = Tunnel(next(i for i in old['inbounds'] if i['tag'] == tag))
                tunnels[tag] = tunnel
                before[tag] = tunnel.query()
        log = (folder / 'watchdog.log').open('ab')
        watchdog = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'watchdog', str(folder)],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        (folder / 'watchdog.pid').write_text(str(watchdog.pid))
        started = time.monotonic()
        try:
            apply_routing(folder / 'routing-after.json')
            save_template(old_raw, new_raw)
            save_runtime(old, new)
            after = {tag: tunnel.query() for tag, tunnel in tunnels.items()}
            live_routes = route_checks(panel)
            panel_template_check(panel, new_template)
            exits = {}
            for tag, (protocol, port) in TARGETS.items():
                if protocol == 'wireguard':
                    continue
                accounts = next(i for i in old['inbounds'] if i['tag'] == tag)['settings']['accounts']
                for index, account in enumerate(accounts):
                    for scheme in (['http', 'socks5h'] if protocol == 'mixed' else ['http']):
                        if time.monotonic() - started > 130:
                            raise RuntimeError('Verification deadline exceeded')
                        address = probe(scheme + '://127.0.0.1:' + str(port), account)
                        if address != expected:
                            raise RuntimeError('Wrong exit IP on ' + tag + '/' + scheme)
                        exits[f'{tag}/{scheme}/account-{index + 1}'] = address
            # Verify SOCKS UDP through the common pool without borrowing an
            # existing WireGuard peer key (that would move its live endpoint).
            udp_dns(11090)
            if pids != xray_pids() or old['inbounds'] != json.loads(CONFIG.read_text())['inbounds']:
                raise RuntimeError('VPN process or inbound configuration changed')
            report = {'targets': list(TARGETS), 'new_connection_exit_ips': exits,
                      'established_tunnel_before': before, 'established_tunnel_after': after,
                      'live_route_checks': live_routes, 'pool_udp_dns': 'passed',
                      'main_xray_pids': pids, 'inbounds_unchanged': True,
                      'inbounds_sha256': hashlib.sha256(json.dumps(old['inbounds'], sort_keys=True).encode()).hexdigest(),
                      'wireguard_peer_keys_used_for_testing': False, 'rollback_directory': str(folder)}
            with (folder / 'lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if (folder / 'rolled-back').exists() or template_raw() != new_raw or json.loads(CONFIG.read_text()) != new:
                    raise RuntimeError('Configuration changed during verification')
                (folder / 'report.json').write_text(json.dumps(report, indent=2))
                (folder / 'committed').write_text('Validated without process or input changes\n')
            print(json.dumps(report))
        except BaseException:
            rollback(folder)
            raise
    finally:
        for tunnel in tunnels.values():
            tunnel.close()
        panel.close()


if __name__ == '__main__':
    main()
