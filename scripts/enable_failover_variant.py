#!/usr/bin/env python3
"""Add one source-bound route to main Xray without reloading x-ui or VPN.

Deploy only after the second SOCKS pool is running and before publishing or
starting its frontend. The existing 46738 entry and all old routes are retained.
"""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import uuid

XRAY = Path('/usr/local/x-ui/bin/xray-linux-amd64')
CONFIG = XRAY.with_name('config.json')
DB = Path('/etc/x-ui/x-ui.db')
BACKUPS = Path('/var/backups/vpn-infra')
LOCK = Path('/run/lock/vpn-failover-variant.lock')
API = 62789
VARIANT_API = 11093
INBOUND = 'in-46738-tcp'
PORT = 46738
SOURCE = '127.0.0.2'
LEGACY = 'vpn-egress-pool'
OUT = 'vpn-failover-egress-pool'
RULE = 'vpn-failover-source-127-0-0-2'
VARIANT_OUT = {'tag': OUT, 'protocol': 'socks',
               'settings': {'address': '127.0.0.1', 'port': 11092}}
VARIANT_RULE = {'type': 'field', 'ruleTag': RULE, 'inboundTag': [INBOUND],
                'source': [SOURCE + '/32'], 'outboundTag': OUT}
OLD_RULE = {'type': 'field', 'inboundTag': [INBOUND], 'outboundTag': LEGACY}
LEADING_RULES = [
    {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
    {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'blocked'},
    {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'blocked'},
]


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def active_rule(rule):
    return {k: v for k, v in rule.items() if k != 'enabled'}


def normalized_routing(routing):
    return dict(routing, rules=[active_rule(r) for r in routing['rules'] if r.get('enabled', True)])


def transform(config):
    """Preserve every pre-existing field; insert one rule and append one handler."""
    routing = config['routing']
    rules = routing['rules']
    need(not (routing.get('script') or routing.get('balancers')),
         'Main routing uses a script or balancers; full rule replacement refused')
    enabled = [active_rule(r) for r in rules if r.get('enabled', True)]
    need(enabled[:3] == LEADING_RULES and not any(r.get('webhook') for r in enabled),
         'Unexpected main API/block policy or rule side effects')
    old = [idx for idx, r in enumerate(rules)
           if r.get('enabled', True) and active_rule(r) == OLD_RULE]
    need(len(old) == 1, 'Legacy VLESS catchall is missing or ambiguous')
    variant_rules = [idx for idx, r in enumerate(rules)
                     if r.get('ruleTag') == RULE or r.get('outboundTag') == OUT]
    expected_old = {'tag': LEGACY, 'protocol': 'socks',
                    'settings': {'address': '127.0.0.1', 'port': 11090}}
    outbounds = config['outbounds']
    tags = [o['tag'] for o in outbounds]
    need(len(tags) == len(set(tags)), 'Duplicate existing outbound tags')
    need([o for o in outbounds if o['tag'] == LEGACY] == [expected_old],
         'Legacy SOCKS handler has changed')
    prefix = [active_rule(r) for r in rules[:old[0]] if r.get('enabled', True)][3:]
    need(all(r == VARIANT_RULE or (r.get('inboundTag') and INBOUND not in r['inboundTag'])
             for r in prefix), 'Another rule can intercept this VLESS input before the old catchall')
    if OUT in tags or variant_rules:
        need([o for o in outbounds if o['tag'] == OUT] == [VARIANT_OUT]
             and variant_rules == [old[0] - 1] and active_rule(rules[old[0] - 1]) == VARIANT_RULE
             and rules[old[0] - 1].get('enabled', True), 'Conflicting existing variant rule or handler')
        return config
    new = copy.deepcopy(config)
    new['outbounds'].append(copy.deepcopy(VARIANT_OUT))
    new['routing']['rules'].insert(old[0], copy.deepcopy(VARIANT_RULE))
    return new


def candidates(runtime, template):
    need(normalized_routing(template['routing']) == runtime['routing'],
         'Runtime routing and panel template differ')
    need(runtime['outbounds'] == template['outbounds'], 'Runtime and template outbounds differ')
    matches = [i for i in runtime['inbounds'] if i.get('tag') == INBOUND]
    need(len(matches) == 1 and matches[0]['port'] == PORT and matches[0]['protocol'] == 'vless',
         'Expected legacy VLESS inbound is missing')
    inbound = matches[0]
    stream = inbound['streamSettings']
    need(stream.get('security', 'none') == 'none' and stream.get('network') in ('tcp', 'raw')
         and inbound['settings'].get('decryption') == 'none'
         and inbound.get('listen') in ('0.0.0.0', '127.0.0.1'), 'Legacy VLESS transport is unexpected')
    need({'HandlerService', 'RoutingService'} <= set(runtime.get('api', {}).get('services', [])),
         'Main loopback API is missing required services')
    new_runtime, new_template = transform(runtime), transform(template)
    need(normalized_routing(new_template['routing']) == new_runtime['routing'],
         'Candidate runtime/template routes differ')
    return new_runtime, new_template, inbound


def command(args):
    env = dict(os.environ, XRAY_LOCATION_ASSET=str(XRAY.parent))
    p = subprocess.run(args, capture_output=True, timeout=12, env=env)
    # CLI diagnostics can contain serialized settings or private identifiers.
    need(p.returncode == 0, 'Xray command failed: ' + ' '.join(map(str, args[1:3])))
    return p.stdout


def api(cmd, *args, port=None):
    return command([str(XRAY), 'api', cmd, f'--server=127.0.0.1:{port or API}', '--timeout=6', *map(str, args)])


def live_rules():
    data = json.loads(api('lsrules'))
    return [(r.get('tag', ''), r.get('ruleTag', '')) for r in data['rules']]


def live_outbounds():
    return {o['tag'] for o in json.loads(api('lso'))['outbounds']}


def rule_projection(config):
    return [(r.get('outboundTag', ''), r.get('ruleTag', '')) for r in config['routing']['rules']]


def pin_live(config):
    need(live_rules() == rule_projection(config), 'Live rule order/tags differ from runtime file')
    tags = {o['tag'] for o in config['outbounds']}
    implicit = {c.get('tag') for c in (config.get('api', {}), config.get('metrics', {}))}
    observed = live_outbounds()
    need(tags <= observed <= tags | implicit, 'Live outbound tags differ from runtime file')
    return observed


def runtime_identity():
    pids = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            if path.read_bytes().split(b'\0')[0] not in (b'bin/xray-linux-amd64', os.fsencode(XRAY)):
                continue
            stat_fields = (path.parent / 'stat').read_text().rsplit(')', 1)[1].split()
            pids.append([int(path.parent.name), stat_fields[19]])  # /proc stat field 22
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    need(len(pids) == 1, 'Could not uniquely identify the main Xray process')
    return pids[0]


def read_template():
    with sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True, timeout=6) as db:
        rows = db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchall()
    need(len(rows) == 1 and isinstance(rows[0][0], str), 'Expected a unique x-ui routing template')
    return rows[0][0].encode()


def write_template(expected, replacement):
    with sqlite3.connect(DB, timeout=6) as db:
        result = db.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig' AND value=?",
                            (replacement.decode(), expected.decode()))
        need(result.rowcount == 1, 'Panel template changed; SQLite compare-and-swap refused')


def write_runtime(expected, replacement):
    stat = CONFIG.stat()
    fd, name = tempfile.mkstemp(prefix='.vpn-failover-', dir=CONFIG.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchown(f.fileno(), stat.st_uid, stat.st_gid)
            os.fchmod(f.fileno(), stat.st_mode & 0o777)
            f.write(replacement)
            f.flush()
            os.fsync(f.fileno())
        current = CONFIG.stat()
        need((current.st_ino, current.st_mtime_ns) == (stat.st_ino, stat.st_mtime_ns)
             and CONFIG.read_bytes() == expected, 'Runtime file changed; compare-and-swap refused')
        os.replace(name, CONFIG)
    finally:
        Path(name).unlink(missing_ok=True)


def pool_uplink():
    name = 'inbound>>>pool-socks>>>traffic>>>uplink'
    response = json.loads(api('statsquery', '--pattern=' + name, port=VARIANT_API))
    counters = [int(s.get('value', 0)) for s in response.get('stat', [])
                if s['name'] == name]
    need(len(counters) == 1, 'The new pool has no unique SOCKS inbound uplink counter')
    return counters[0]


def read_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.read(count - len(chunks))
        if not part:
            break
        chunks.extend(part)
    return bytes(chunks)


def vless_request(uid, source, command_id, port, address, payload):
    sock = socket.create_connection(('127.0.0.1', PORT), timeout=9, source_address=(source, 0))
    try:
        header = b'\0' + uid.bytes + struct.pack('!BBH', 0, command_id, port) + address
        sock.sendall(header + payload)
        with sock.makefile('rb', buffering=0) as stream:
            prefix = read_exact(stream, 2)
            # The server responds with version 0 and no response add-ons.
            need(prefix == b'\0\0', 'VLESS canary was not authenticated')
            if command_id == 2:
                size = read_exact(stream, 2)
                need(len(size) == 2, 'VLESS UDP response is truncated')
                count = int.from_bytes(size, 'big')
                response = read_exact(stream, count)
                need(len(response) == count, 'VLESS UDP payload is truncated')
                return response
        response = http.client.HTTPResponse(sock)
        try:
            response.begin()
            need(response.status == 200, 'Canary did not get an HTTP 200 response')
            return response.read(128)
        finally:
            response.close()
    finally:
        sock.close()


def check_tcp(uid, source, ip):
    domain = b'api.ipify.org'
    addr = bytes((2, len(domain))) + domain
    raw = vless_request(uid, source, 1, 80, addr,
                        b'GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
    need(ipaddress.ip_address(raw.decode().strip()) == ip, 'Unexpected egress address through VLESS canary')


def check_udp(uid, source):
    query = b'\xa9\x2e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    reply = vless_request(uid, source, 2, 53, b'\x01\x01\x01\x01\x01',
                          struct.pack('!H', len(query)) + query)
    need(len(reply) >= 12 and reply[:2] == query[:2] and bool(reply[2] & 128),
         'VLESS UDP canary received no valid DNS response')


def snapshot(folder):
    old_runtime = (folder / 'runtime-before.json').read_bytes()
    new_runtime = (folder / 'runtime-after.json').read_bytes()
    old_template = (folder / 'template-before.json').read_bytes()
    new_template = (folder / 'template-after.json').read_bytes()
    return old_runtime, new_runtime, old_template, new_template


def rollback(folder, force=False):
    if (folder / 'rolled-back').exists() or ((folder / 'committed').exists() and not force):
        return
    old, new, old_template, new_template = snapshot(folder)
    baseline = json.loads((folder / 'baseline.json').read_bytes())
    need(runtime_identity() == baseline['process'], 'Main Xray restarted; automatic rollback refused')
    current, template = CONFIG.read_bytes(), read_template()
    need(current in (old, new) and template in (old_template, new_template),
         'Concurrent runtime/template change; automatic rollback refused')
    live = live_rules()
    before, after = rule_projection(json.loads(old)), rule_projection(json.loads(new))
    old_out = set(baseline['outbounds'])
    live_out = live_outbounds()
    need(live in (before, after) and live_out in (old_out, old_out | {OUT}),
         'Concurrent live API change; automatic rollback refused')
    if live == after:
        api('adrules', folder / 'routing-before.json')
    need(live_rules() == before, 'Previous live routing could not be verified')
    if template == new_template:
        write_template(new_template, old_template)
    if current == new:
        write_runtime(new, old)
    if OUT in live_out:
        api('rmo', OUT)
    need(live_outbounds() == old_out, 'Previous live outbound list could not be verified')
    (folder / 'rolled-back').write_text('Restored main routing, runtime file and template without a restart\n')


def apply(legacy_ip, variant_ip):
    old, old_template = CONFIG.read_bytes(), read_template()
    runtime, template = json.loads(old), json.loads(old_template)
    new_runtime, new_template, inbound = candidates(runtime, template)
    process = runtime_identity()
    old_out = pin_live(runtime)
    if new_runtime == runtime and new_template == template:
        print('Variant route is already present; no changes applied')
        return
    need(OUT not in old_out, 'Variant outbound tag already exists in live Xray')
    uid = next((uuid.UUID(c['id']) for c in inbound['settings']['clients'] if not c.get('flow')), None)
    need(uid is not None, 'No plain VLESS canary user is present')
    check_tcp(uid, '127.0.0.1', legacy_ip)
    check_tcp(uid, SOURCE, legacy_ip)
    # Before the second frontend is enabled this counter must only see our variant probe.
    pool_uplink()
    folder = BACKUPS / ('failover-variant-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    folder.mkdir(mode=0o700)
    new, template_after = json_bytes(new_runtime), json_bytes(new_template)
    for name, data in {'runtime-before.json': old, 'runtime-after.json': new,
                       'template-before.json': old_template, 'template-after.json': template_after,
                       'routing-before.json': json_bytes({'routing': runtime['routing']}),
                       'routing-after.json': json_bytes({'routing': new_runtime['routing']}),
                       'outbound.json': json_bytes({'outbounds': [VARIANT_OUT]}),
                       'baseline.json': json_bytes({'process': process, 'outbounds': sorted(old_out)})}.items():
        (folder / name).write_bytes(data)
    command([str(XRAY), 'run', '-test', '-config', str(folder / 'runtime-after.json')])
    need(CONFIG.read_bytes() == old and read_template() == old_template and runtime_identity() == process
         and pin_live(runtime) == old_out, 'Main VPN changed during preflight')
    with (folder / 'watchdog.log').open('ab') as log:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'watchdog', str(folder)],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    try:
        api('ado', folder / 'outbound.json')
        need(live_outbounds() == old_out | {OUT} and live_rules() == rule_projection(runtime),
             'Unexpected live API changes after adding the handler')
        api('adrules', folder / 'routing-after.json')
        need(live_rules() == rule_projection(new_runtime), 'Live rule order was not updated')
        pre = pool_uplink()
        check_tcp(uid, '127.0.0.1', legacy_ip)
        check_udp(uid, '127.0.0.1')
        need(pool_uplink() == pre, 'Legacy VLESS touched the variant pool')
        check_tcp(uid, SOURCE, variant_ip)
        check_udp(uid, SOURCE)
        need(pool_uplink() > pre, 'Source-bound VLESS did not reach the variant pool')
        need(runtime_identity() == process and CONFIG.read_bytes() == old and read_template() == old_template,
             'Main VPN changed during verification')
        write_template(old_template, template_after)
        write_runtime(old, new)
        need(runtime_identity() == process and pin_live(new_runtime) == old_out | {OUT}
             and CONFIG.read_bytes() == new and read_template() == template_after,
             'Main VPN changed while persisting the variant')
        (folder / 'committed').write_text('Verified source isolation, TCP, UDP and unchanged process\n')
    except BaseException:
        rollback(folder)
        raise
    print(json.dumps({'main_xray_pid': process[0], 'legacy_exit': str(legacy_ip), 'variant_exit': str(variant_ip),
                      'tcp_and_udp': 'passed', 'rollback_directory': str(folder)}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    plan = sub.add_parser('plan', help='read-only check of local JSON snapshots')
    plan.add_argument('runtime', type=Path)
    plan.add_argument('template', type=Path)
    mutation = sub.add_parser('apply')
    mutation.add_argument('--legacy-ip', type=ipaddress.ip_address, required=True)
    mutation.add_argument('--variant-ip', type=ipaddress.ip_address, required=True)
    for action in ('watchdog', 'rollback'):
        sub.add_parser(action).add_argument('folder', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            config = json.loads(args.runtime.read_bytes())
            proposed, _, _ = candidates(config, json.loads(args.template.read_bytes()))
            print(json.dumps({'already_configured': proposed == config, 'route': VARIANT_RULE,
                              'outbound': VARIANT_OUT}))
            return
        need(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Live operations require root on entry')
        if args.action == 'watchdog':
            time.sleep(105)
        with LOCK.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == 'apply':
                apply(args.legacy_ip, args.variant_ip)
            else:
                folder = args.folder.resolve()
                need(folder.parent == BACKUPS and folder.name.startswith('failover-variant-'),
                     'Expected a private failover-variant backup directory')
                rollback(folder, force=args.action == 'rollback')
    except (ValueError, KeyError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        # The fixed errors are safe; parser/OS diagnostics may mention input data.
        parser.exit(1, 'enable-failover-variant: ' + (str(exc) if type(exc) is RuntimeError else type(exc).__name__) + '\n')


if __name__ == '__main__':
    main()
