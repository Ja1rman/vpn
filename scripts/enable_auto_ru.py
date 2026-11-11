#!/usr/bin/env python3
"""Add Russian TLD routing to the running VPN Auto pool only."""
import argparse
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from auto_ru_routes import add_direct_ru, DIRECT_TAG, HOP_TAG, SNIFF_TAG, SNIFF_PORT
import update_failover_pool as pool


MYIP = 'https://myip.ru/index_small.php'
FOREIGN_IP = 'https://api.ipify.org'
RF = 'https://xn--90aivcdt6dxbc.xn--p1ai/'
LEGACY = Path('/etc/vpn-balancer/config.json')


def curl(url, socks=None, *, literal=False, head=False):
    args = ['curl', '-q', '-4', '--silent', '--fail', '--show-error', '--max-time', '10']
    if socks is None:
        args += ['--noproxy', '*']
    else:
        args += ['--noproxy', '', '--socks5' if literal else '--socks5-hostname', f'127.0.0.1:{socks}']
    if head:
        args += ['--head', '--output', '/dev/null']
    return pool.command(args + [url], 'HTTPS canary')


def myip(address, port=None, *, literal=False):
    result = curl(MYIP, port, literal=literal)
    return re.search(rb'(?<![.0-9])' + re.escape(address.encode()) + rb'(?![.0-9])', result) is not None


def inbound_descriptors(api_address=None):
    values = json.loads(pool.api('lsi', address=api_address))['inbounds']
    result = {v['tag']: v for v in values}
    pool.require(len(result) == len(values), 'Duplicate live inbound')
    return result


def downlink(api_address=None):
    result = json.loads(pool.api('statsquery', '--pattern=outbound>>>' + DIRECT_TAG + '>>>traffic>>>downlink',
                                 address=api_address))
    return sum(int(v['value']) for v in result.get('stat', []))


def smoke(address, port, api_address=None):
    pool.require(myip(address, port), 'A .ru hostname did not exit through the entry IPv4')
    pool.require(myip(address, port, literal=True), 'A .ru TLS request sent by IPv4 did not exit through the entry')
    before = downlink(api_address)
    curl(RF, port, head=True)
    pool.require(downlink(api_address) > before, 'The .рф HTTPS request did not increment the direct route counter')
    for literal in (False, True):
        foreign = curl(FOREIGN_IP, port, literal=literal).decode().strip()
        pool.require(foreign and foreign != address, 'A foreign HTTPS request did not use the foreign pool')
    pool.udp_dns(port)


def free_ports(n):
    sockets = [socket.socket() for _ in range(n)]
    try:
        for s in sockets:
            s.bind(('127.0.0.1', 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


@contextmanager
def temporary_core(config, work, logfile):
    endpoint = work / 'api.sock'
    config['api']['listen'] = str(endpoint)
    path = work / 'config.json'
    path.write_bytes(pool.encode(config))
    with logfile.open('wb') as log:
        proc = subprocess.Popen([str(pool.XRAY), 'run', '-config', str(path)], stdout=log, stderr=log,
                                env=dict(os.environ, XRAY_LOCATION_ASSET=str(pool.ASSETS)))
        try:
            for _ in range(30):
                pool.require(proc.poll() is None, 'Isolated Xray failed to start; see private log')
                if endpoint.exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('Isolated Xray API unavailable')
            yield 'unix://' + str(endpoint)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


def check_isolated(config, address, backup):
    candidate = copy.deepcopy(config)
    candidate['inbounds'] = [i for i in candidate['inbounds'] if i['tag'] != 'api']
    ports = dict(zip((i['tag'] for i in candidate['inbounds']), free_ports(len(candidate['inbounds']))))
    for i in candidate['inbounds']:
        i['port'] = ports[i['tag']]
    next(o for o in candidate['outbounds'] if o['tag'] == HOP_TAG)['settings']['port'] = ports[SNIFF_TAG]
    with tempfile.TemporaryDirectory(prefix='auto-ru-test-') as d:
        with temporary_core(candidate, Path(d), backup / 'isolated.log') as api_address:
            smoke(address, ports['pool-socks'], api_address)
    # Read exact normalized outbound settings from a private API. The local
    # forwarding port in this instance is the real one, but no traffic is sent.
    candidate = copy.deepcopy(config)
    candidate['inbounds'] = [i for i in candidate['inbounds'] if i['tag'] == SNIFF_TAG]
    candidate['inbounds'][0]['port'] = free_ports(1)[0]
    with tempfile.TemporaryDirectory(prefix='auto-ru-compile-') as d:
        with temporary_core(candidate, Path(d), backup / 'compiled.log') as api_address:
            handlers = pool.fingerprints(api_address)
            inbound = inbound_descriptors(api_address)[SNIFF_TAG]
    inbound['receiverSettings']['portList'] = SNIFF_PORT
    return inbound, {tag: handlers[tag] for tag in (DIRECT_TAG, HOP_TAG)}


def apply(address):
    pool.private_config_stat()
    old_raw, legacy = pool.CONFIG.read_bytes(), LEGACY.read_bytes()
    old = json.loads(old_raw)
    pool.config_sites(old)
    instance, before, inbounds = pool.pid(), pool.fingerprints(), inbound_descriptors()
    pool.pin_live(old, before)
    if any(o['tag'] == DIRECT_TAG for o in old['outbounds']):
        smoke(address, pool.SOCKS)
        print('VPN Auto direct routing already present and verified')
        return
    desired = add_direct_ru(old, address)
    pool.config_sites(desired)
    pool.require(myip(address), 'The entry does not currently exit through the expected IPv4')
    backup = pool.BACKUPS / ('failover-pool-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-direct-ru')
    backup.mkdir(mode=0o700)
    new_raw = pool.encode(desired)
    for name, data in {'before.json': old_raw, 'after.json': new_raw,
                       'routing-before.json': pool.encode({'routing': old['routing']}),
                       'routing-after.json': pool.encode({'routing': desired['routing']})}.items():
        (backup / name).write_bytes(data)
    print('Private route backup: ' + str(backup), flush=True)
    pool.command([str(pool.XRAY), 'run', '-test', '-config', str(backup / 'after.json')], 'config validation', backup)
    listener, additions = check_isolated(desired, address, backup)
    pool.require(all(before.get(tag, fp) == fp for tag, fp in additions.items()),
                 'An existing direct handler has different settings')
    pool.require(inbounds.get(SNIFF_TAG, listener) == listener, 'An existing sniff listener has different settings')
    after, expected_inbounds = before | additions, inbounds | {SNIFF_TAG: listener}
    new_handlers = [o for o in desired['outbounds'] if o['tag'] in additions.keys() - before.keys()]
    (backup / 'outbound.json').write_bytes(pool.encode({'outbounds': new_handlers}))
    (backup / 'inbound.json').write_bytes(pool.encode({'inbounds': [i for i in desired['inbounds'] if i['tag'] == SNIFF_TAG]}))
    (backup / 'transaction.json').write_bytes(pool.encode({'pid': instance, 'before': before, 'after': after}))
    pool.require(instance == pool.pid() and pool.CONFIG.read_bytes() == old_raw and pool.fingerprints() == before
                 and inbound_descriptors() == inbounds, 'VPN Auto changed during the test')
    pool.pin_live(old, before)
    updater = Path(pool.__file__).resolve()
    with (backup / 'watchdog.log').open('ab') as log:
        subprocess.Popen([sys.executable, str(updater), '--watchdog', str(backup)], stdin=subprocess.DEVNULL,
                         stdout=log, stderr=log, start_new_session=True)
    try:
        if SNIFF_TAG not in inbounds:
            pool.api('adi', backup / 'inbound.json', backup=backup)
        if new_handlers:
            pool.api('ado', backup / 'outbound.json', backup=backup)
        pool.require(pool.fingerprints() == after and inbound_descriptors() == expected_inbounds,
                     'New live handlers do not match the tested configuration')
        pool.pin_live(old, after)
        pool.api('adrules', backup / 'routing-after.json', backup=backup)
        pool.pin_live(desired, after)
        smoke(address, pool.SOCKS)
        pool.require(instance == pool.pid() and LEGACY.read_bytes() == legacy,
                     'Pool process or legacy configuration changed')
        pool.persist(old_raw, new_raw)
        (backup / 'committed').write_text('Direct .ru/.рф checks, foreign HTTPS and UDP passed without restart\n')
    except BaseException:
        # New loopback listeners and handlers may already have connections.
        # Restoring the old route stops selecting them without interrupting users.
        pool.rollback(backup)
        raise
    print(json.dumps({'direct_ipv4': address, 'pool_pid': instance[0], 'https_and_udp': 'passed'}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path)
    args = parser.parse_args()
    try:
        address = json.loads(args.inventory.read_text())['failover']['direct_ru_ipv4']
        with pool.locked():
            apply(address)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'enable-auto-ru: ' + detail + '\n')


if __name__ == '__main__':
    main()
