#!/usr/bin/env python3
"""Hot-append independent VLESS exits to VPN Auto without restarting it.

Run on the entry server as root with a staged inventory and sibling outbounds/
directory. Existing exits, priorities, listeners, and the old VPN are retained.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from auto_ru_routes import BASE_RULES, DIRECT_TAG, SNIFF_TAG, add_direct_ru
from failover_variant import MAIN, OLD_POOL, build_pool
from priority_pool import build_priority_chain

UNIT = 'vpn-failover-pool.service'
ASSETS = Path('/opt/vpn-failover/pool')
XRAY = ASSETS / 'xray'
CONFIG = Path('/etc/vpn-failover/pool.json')
LOCK = Path('/run/lock/vpn-failover-pool-update.lock')
BACKUPS = Path('/var/backups/vpn-infra')
SOCKS = 11092
API = 11093
BLOCKED = {'tag': 'blocked', 'protocol': 'blackhole', 'settings': {}}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def encode(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def config_sites(config):
    """Validate the whole supported topology, not just individual tag names."""
    outbounds = config['outbounds']
    sites = [o for o in outbounds if o['tag'].startswith('pool-site-')]
    require(len(sites) >= 2 and all(o['protocol'] == 'vless' and
            o.get('streamSettings', {}).get('security') in ('tls', 'reality') for o in sites),
            'VPN Auto must have at least two encrypted VLESS sites')
    bridges, rules, balancers = build_priority_chain([o['tag'] for o in sites])
    inbounds = [i for i in config['inbounds'] if i['tag'] != SNIFF_TAG]
    listeners = {i['tag']: (i.get('listen'), i.get('port')) for i in inbounds}
    require(len(inbounds) == 2 and listeners == {
        'api': ('127.0.0.1', API), 'pool-socks': ('127.0.0.1', SOCKS),
    }, 'This configuration is not the isolated VPN Auto pool')
    expected = dict(config, inbounds=inbounds, outbounds=[BLOCKED] + sites + bridges,
                    routing={'domainStrategy': 'AsIs', 'rules': BASE_RULES + rules, 'balancers': balancers})
    direct = [o for o in outbounds if o['tag'] == DIRECT_TAG]
    if direct:
        try:
            block = direct[0]['settings']['finalRules'][0]['ip'][1]
            address = block.removesuffix('/32')
            expected = add_direct_ru(expected, address)
        except (ValueError, IndexError, KeyError, TypeError, AttributeError):
            raise RuntimeError('Unexpected VPN Auto direct topology; hot update refused') from None
    require(expected == config, 'Unexpected VPN Auto topology; hot update refused')
    return sites


def append_plan(old, new):
    current, desired = config_sites(old), config_sites(new)
    require({k: v for k, v in old.items() if k not in ('routing', 'outbounds')} ==
            {k: v for k, v in new.items() if k not in ('routing', 'outbounds')},
            'Pool settings other than routes and outbounds changed; hot update refused')
    require(desired[:len(current)] == current,
            'Keep all existing egresses and their order unchanged; add new egresses at the end')
    old_by_tag = {o['tag']: o for o in old['outbounds']}
    require(all(o['tag'] not in old_by_tag or old_by_tag[o['tag']] == o for o in new['outbounds']),
            'An existing outbound definition changed; hot update refused')
    return (desired[len(current):], [o for o in new['outbounds'] if o['tag'] not in old_by_tag])


def command(args, phase, backup=None, *, data=None, timeout=15):
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout,
                                env=dict(os.environ, XRAY_LOCATION_ASSET=str(ASSETS)))
    except subprocess.TimeoutExpired as exc:
        if backup:
            (backup / (phase + '.log')).write_bytes((exc.stdout or b'') + b'\n' + (exc.stderr or b''))
        raise RuntimeError(phase + ' timed out') from None
    if result.returncode != 0:
        if backup:
            (backup / (phase + '.log')).write_bytes(result.stdout + b'\n' + result.stderr)
        raise RuntimeError(phase + ' failed; diagnostic output is private')
    return result.stdout


def api(command_name, *args, address=None, backup=None):
    return command([str(XRAY), 'api', command_name, '--server=' + (address or f'127.0.0.1:{API}'),
                    '--timeout=6', *map(str, args)], 'api-' + command_name, backup)


def pid():
    output = command(['systemctl', 'show', UNIT, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'InvocationID'],
                     'service-state').decode()
    status = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    require(status.get('ActiveState') == 'active' and int(status.get('MainPID', '0')) > 0
            and bool(status.get('InvocationID')), 'VPN Auto is not active')
    return [int(status['MainPID']), status['InvocationID']]


def fingerprints(address=None):
    # ListOutbounds includes the full normalized protocol settings; never log it.
    outbounds = json.loads(api('lso', address=address))['outbounds']
    result = {o['tag']: hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest() for o in outbounds}
    require(len(result) == len(outbounds), 'Live Xray reports duplicate outbound tags')
    return result


def expected_rules(config):
    return [(r.get('outboundTag', ''), r.get('ruleTag', '')) for r in config['routing']['rules']]


def live_rules():
    return [(r.get('tag', ''), r.get('ruleTag', '')) for r in json.loads(api('lsrules'))['rules']]


def selector_guard(config, tags):
    for balancer in config['routing']['balancers']:
        selector = balancer['selector'][0]
        require([t for t in tags if t.startswith(selector)] == [selector],
                'A retained runtime outbound collides with a priority selector; choose a distinct egress name')


def pin_live(config, handlers):
    require(live_rules() == expected_rules(config), 'Live VPN Auto rule list differs from the config file')
    require({o['tag'] for o in config['outbounds']} <= handlers.keys(), 'Expected live outbound is missing')
    selector_guard(config, handlers)
    for balancer in config['routing']['balancers']:
        reply = api('bi', balancer['tag']).decode()
        require('Selects:' in reply, 'Unrecognized live balancer selector output')
        override, selects = reply.split('Selects:', 1)
        rows = r'^[ \t]*\d+[ \t]+(\S+)[ \t]*$'
        # Xray also prints "Selecting Override" with an empty target.
        require(not re.findall(rows, override, re.MULTILINE), 'A live balancer has an override')
        selected = re.findall(rows, selects, re.MULTILINE)
        require(selected == balancer['selector'], 'Live priority selector does not select exactly its intended exit')


def read_exact(sock, count):
    buffer = bytearray()
    while len(buffer) < count:
        data = sock.recv(count - len(buffer))
        require(bool(data), 'SOCKS connection ended early')
        buffer.extend(data)
    return bytes(buffer)


def udp_dns(port, account=None):
    with socket.create_connection(('127.0.0.1', port), timeout=6) as control:
        method = b'\x02' if account else b'\x00'
        control.sendall(b'\x05\x01' + method)
        require(read_exact(control, 2) == b'\x05' + method, 'SOCKS UDP greeting failed')
        if account:
            user, password = (value.encode() for value in account)
            control.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
            require(read_exact(control, 2) == b'\x01\x00', 'SOCKS UDP authentication failed')
        control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00')
        require(read_exact(control, 4) == b'\x05\x00\x00\x01', 'SOCKS UDP associate failed')
        ip, relay_port = struct.unpack('!4sH', read_exact(control, 6))
        require(ip in (b'\0\0\0\0', b'\x7f\0\0\x01') and relay_port,
                'SOCKS UDP relay did not return a local IPv4 socket')
        token = secrets.token_bytes(2)
        query = token + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        target = b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.connect(('127.0.0.1', relay_port))
            udp.send(target + query)
            response = udp.recv(4096)
        require(len(response) >= 22 and response[:10] == target and response[10:12] == token
                and bool(response[12] & 128) and response[13] & 15 == 0,
                'VPN Auto UDP canary did not receive a valid DNS reply')


def https_probe(port, urls, account=None, backup=None, label='probe'):
    for index, url in enumerate(urls):
        config = 'url = ' + json.dumps(url) + '\n'
        if account:
            config += 'proxy-user = ' + json.dumps(':'.join(account)) + '\n'
        try:
            output = command(['curl', '-q', '--silent', '--show-error', '--fail', '--max-time', '12',
                              '--connect-timeout', '6', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
                              '--output', '/dev/null', '--write-out', '%{http_code}', '--config', '-'],
                             f'{label}-https-{index + 1}', backup, data=config.encode())
            if output == b'204':
                return
        except RuntimeError:
            continue
    raise RuntimeError(label + ' did not receive HTTPS 204 from a configured endpoint')


def probe(port, urls, account=None, backup=None, label='probe'):
    https_probe(port, urls, account, backup, label)
    try:
        udp_dns(port, account)
    except (OSError, RuntimeError):
        raise RuntimeError(label + ' UDP DNS probe failed') from None


def isolated_probe(config, sites, urls, backup):
    # Reserve ports together so probes do not accidentally allocate duplicates.
    sockets = [socket.socket() for _ in sites]
    try:
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    user, password = secrets.token_hex(12), secrets.token_hex(24)
    inbounds, rules = [], []
    for index, (site, listen) in enumerate(zip(sites, ports)):
        tag = 'probe-' + str(index)
        inbounds.append({'listen': '127.0.0.1', 'port': listen, 'tag': tag, 'protocol': 'socks',
                         'settings': {'auth': 'password', 'accounts': [{'user': user, 'pass': password}], 'udp': True}})
        rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': site['tag']})
    with tempfile.TemporaryDirectory(prefix='vpn-auto-', dir='/tmp') as work, (backup / 'canary.log').open('wb') as log:
        # HandlerService can read credentials; its socket is inside a 0700 directory.
        endpoint = Path(work) / 'api.sock'
        canary = {'log': {'loglevel': 'warning', 'access': 'none'},
                  'api': {'tag': 'api', 'listen': str(endpoint), 'services': ['HandlerService']},
                  'inbounds': inbounds, 'outbounds': config['outbounds'], 'routing': {'rules': rules}}
        path = Path(work) / 'canary.json'
        path.write_bytes(encode(canary))
        process = subprocess.Popen([str(XRAY), 'run', '-config', str(path)], stdout=log, stderr=log,
                                   env=dict(os.environ, XRAY_LOCATION_ASSET=str(ASSETS)))
        try:
            for _ in range(30):
                require(process.poll() is None, 'Isolated Xray canary exited; see private canary.log')
                try:
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(0.25)
                        client.connect(str(endpoint))
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Isolated Xray API did not start')
            compiled = fingerprints('unix://' + str(endpoint))
            for index, listen in enumerate(ports, 1):
                probe(listen, urls, (user, password), backup, 'new-egress-' + str(index))
            require(process.poll() is None, 'Isolated Xray canary stopped during probes')
            return compiled
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def private_config_stat():
    info = CONFIG.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 0,
            'Expected a root-owned regular VPN Auto config with mode 0600')
    return info


def persist(expected, replacement):
    info = private_config_stat()
    fd, temp = tempfile.mkstemp(prefix='.vpn-auto-', dir=CONFIG.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        current = private_config_stat()
        require((info.st_ino, info.st_mtime_ns) == (current.st_ino, current.st_mtime_ns)
                and CONFIG.read_bytes() == expected, 'Pool config changed concurrently; refusing to overwrite it')
        os.replace(temp, CONFIG)
        fd_dir = os.open(CONFIG.parent, os.O_RDONLY)
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)
    finally:
        Path(temp).unlink(missing_ok=True)


@contextmanager
def locked():
    with LOCK.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def rollback(backup, force=False):
    if (backup / 'rolled-back').exists() or ((backup / 'committed').exists() and not force):
        return
    state = json.loads((backup / 'transaction.json').read_bytes())
    old, new = ((backup / name).read_bytes() for name in ('before.json', 'after.json'))
    current = CONFIG.read_bytes()
    require(current in (old, new) and pid() == state['pid'],
            'Pool config or process changed concurrently; automatic rollback refused')
    existing = fingerprints()
    before, after = state['before'], state['after']
    require(before.items() <= existing.items() <= after.items(),
            'Live outbounds changed concurrently; automatic rollback refused')
    previous, candidate = expected_rules(json.loads(old)), expected_rules(json.loads(new))
    live = live_rules()
    require(live in (previous, candidate), 'Live routing changed concurrently; automatic rollback refused')
    if live == candidate:
        api('adrules', backup / 'routing-before.json', backup=backup)
    pin_live(json.loads(old), existing)
    if current == new:
        persist(new, old)
    # Never remove handlers: connections created while the new route was active
    # may still use them. Retries can reuse an exact compiled configuration.
    (backup / 'rolled-back').write_text('Old route and config restored; staged handlers retained\n')


def update(inventory, *, check_only=False):
    settings = json.loads(inventory.read_bytes())['failover']
    urls = settings['probe_urls']
    require(isinstance(urls, list) and bool(urls) and all(
        urlsplit(url).scheme == 'https' and urlsplit(url).hostname and not urlsplit(url).username for url in urls),
        'VPN Auto canaries require valid HTTPS probe URLs')
    desired, names = build_pool(settings, json.loads(MAIN.read_bytes()), json.loads(OLD_POOL.read_bytes()),
                                private_folder=inventory.parent / 'outbounds')
    private_config_stat()
    old_raw = CONFIG.read_bytes()
    old = json.loads(old_raw)
    sites, additions = append_plan(old, desired)
    instance, previous = pid(), fingerprints()
    pin_live(old, previous)
    if not sites:
        require(desired == old and old_raw == CONFIG.read_bytes() and instance == pid(),
                'Pool changed during the no-op check')
        print('VPN Auto configuration already matches; no changes applied')
        return
    selector_guard(desired, previous.keys() | {o['tag'] for o in additions})
    require(not check_only, 'The inventory would append exits; check-only mode did not modify VPN Auto')
    backup = BACKUPS / ('failover-pool-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(mode=0o700)
    new_raw = encode(desired)
    for name, contents in {'before.json': old_raw, 'after.json': new_raw,
                           'routing-before.json': encode({'routing': old['routing']}),
                           'routing-after.json': encode({'routing': desired['routing']})}.items():
        (backup / name).write_bytes(contents)
    try:
        command([str(XRAY), 'run', '-test', '-config', str(backup / 'after.json')], 'candidate-validation', backup)
        compiled = isolated_probe(desired, sites, urls, backup)
        require(all(previous.get(o['tag'], compiled[o['tag']]) == compiled[o['tag']] for o in additions),
                'A retained handler has different settings; choose a distinct egress name')
        missing = [o for o in additions if o['tag'] not in previous]
        after = dict(previous, **{o['tag']: compiled[o['tag']] for o in missing})
        probe(SOCKS, urls, backup=backup, label='baseline')
        require(instance == pid() and old_raw == CONFIG.read_bytes() and previous == fingerprints(),
                'Pool changed during candidate verification')
        pin_live(old, previous)
        (backup / 'additions.json').write_bytes(encode({'outbounds': missing}))
        (backup / 'transaction.json').write_bytes(encode({'pid': instance, 'before': previous, 'after': after}))
        with (backup / 'watchdog.log').open('ab') as log:
            subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--watchdog', str(backup)],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            if missing:
                api('ado', backup / 'additions.json', backup=backup)
            require(fingerprints() == after and live_rules() == expected_rules(old) and pid() == instance
                    and CONFIG.read_bytes() == old_raw, 'Pool changed before switching routes')
            api('adrules', backup / 'routing-after.json', backup=backup)
            pin_live(desired, after)
            probe(SOCKS, urls, backup=backup, label='updated')
            require(instance == pid() and fingerprints() == after, 'Pool process or outbounds changed during verification')
            persist(old_raw, new_raw)
            require(instance == pid() and CONFIG.read_bytes() == new_raw, 'Pool changed while persisting the update')
            (backup / 'committed').write_text('HTTPS and UDP verified; VPN Auto process unchanged\n')
        except BaseException:
            rollback(backup)
            raise
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        raise RuntimeError(detail + '; backup: ' + str(backup)) from None
    print(json.dumps({'appended': names[-len(sites):], 'pid': instance[0], 'https_and_udp': 'passed',
                      'rollback_directory': str(backup)}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('inventory', nargs='?', type=Path)
    action.add_argument('--rollback', type=Path)
    action.add_argument('--watchdog', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--check-only', action='store_true', help='Verify a matching inventory without writes')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Run as root on the Linux entry server')
        if args.check_only:
            require(args.inventory is not None, '--check-only requires an inventory')
            update(args.inventory, check_only=True)
            return
        if args.watchdog:
            time.sleep(180)
        with locked():
            if args.inventory:
                update(args.inventory)
            else:
                backup = (args.rollback or args.watchdog).resolve()
                require(backup.parent == BACKUPS and backup.name.startswith('failover-pool-')
                        and backup.stat().st_uid == 0 and stat.S_IMODE(backup.stat().st_mode) == 0o700,
                        'Expected a root-private VPN Auto backup directory')
                rollback(backup, force=bool(args.rollback))
                if args.rollback:
                    print('Previous VPN Auto routing and config restored without a restart')
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'update-failover-pool: ' + detail + '\n')


if __name__ == '__main__':
    main()
