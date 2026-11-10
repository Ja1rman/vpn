#!/usr/bin/env python3
"""Build and start a parallel VPN variant from local, already authorized outbounds."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time

from priority_pool import build_priority_chain

ROOT = Path('/etc/vpn-failover')
MAIN = Path('/usr/local/x-ui/bin/config.json')
OLD_POOL = Path('/etc/vpn-balancer/config.json')
OLD_FRONTEND = Path('/etc/vpn-compatible-vless/config.json')
XRAY = Path('/opt/vpn-balancer/xray')
SING_BOX = Path('/opt/vpn-compatible-vless/sing-box')
SOURCE_IP = '127.0.0.2'
PORTS = {'pool': (11092, 11093), 'entry': (33174,)}


def private_outbound_file(item):
    name = item.get('file')
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_-]+\.json', name):
        raise ValueError('Invalid private outbound filename')
    return name


def build_pool(settings, main, old, private_folder=None):
    config = copy.deepcopy(old)
    ports = {i['tag']: i for i in config['inbounds']}
    if set(ports) != {'pool-socks', 'api'}:
        raise ValueError('Unexpected source pool listeners')
    for tag, port in zip(('pool-socks', 'api'), PORTS['pool']):
        ports[tag].update(listen='127.0.0.1', port=port)
    exports = {'main': main['outbounds'], 'legacy': old['outbounds']}
    outbounds, addresses, names = [], set(), []
    for item in settings['egresses']:
        name = item['name']
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', name):
            raise ValueError('Invalid egress name')
        if item['source'] == 'file':
            if private_folder is None:
                raise ValueError('Private outbound directory not provided')
            source = private_folder / private_outbound_file(item)
            if source.is_symlink() or not source.is_file():
                raise ValueError('Private outbound file missing: ' + name)
            outbound = json.loads(source.read_text())
        else:
            choices = [o for o in exports[item['source']] if o.get('tag') == item['tag']]
            if len(choices) != 1:
                raise ValueError('Configured egress not found: ' + name)
            outbound = copy.deepcopy(choices[0])
        if outbound['protocol'] != 'vless' or outbound.get('streamSettings', {}).get('security') not in ('tls', 'reality'):
            raise ValueError('Egress must be encrypted VLESS: ' + name)
        if outbound.get('proxySettings') or outbound.get('streamSettings', {}).get('sockopt', {}).get('dialerProxy'):
            raise ValueError('External dependency on another local outbound: ' + name)
        endpoint = outbound['settings']
        if 'address' not in endpoint:
            servers = endpoint.get('vnext', [])
            if not isinstance(servers, list) or len(servers) != 1:
                raise ValueError('Expected one VLESS endpoint: ' + name)
            endpoint = servers[0]
        address = str(ipaddress.ip_address(endpoint['address']))
        if address != item['address'] or address in addresses or not ipaddress.ip_address(address).is_global:
            raise ValueError('Egress address differs or is not distinct: ' + name)
        addresses.add(address)
        names.append(name)
        outbound['tag'] = 'pool-site-' + name
        outbounds.append(outbound)
    if len(addresses) < 2:
        raise ValueError('At least two independent egress addresses required')
    bridges, rules, balancers = build_priority_chain([o['tag'] for o in outbounds])
    config['outbounds'] = [{'tag': 'blocked', 'protocol': 'blackhole', 'settings': {}}] + outbounds + bridges
    config['routing'] = {'domainStrategy': 'AsIs', 'rules': [
        {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
        {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'blocked'},
        {'type': 'field', 'inboundTag': ['pool-socks'], 'balancerTag': 'vpn-pool'},
    ] + rules, 'balancers': balancers}
    config['observatory'] = {'subjectSelector': ['pool-site-'], 'probeUrl': settings['probe_urls'][0],
                             'probeInterval': '10s', 'enableConcurrency': True}
    config['policy']['system'].update(statsInboundUplink=True, statsInboundDownlink=True)
    config['log'] = {'loglevel': 'warning', 'access': 'none'}
    return config, names


def build_entry(old):
    config = copy.deepcopy(old)
    if len(config['inbounds']) != 1:
        raise ValueError('Expected one compatibility frontend')
    inbound = config['inbounds'][0]
    if inbound['type'] != 'vless' or inbound['listen_port'] != 33173 or not inbound['tls']['reality']['enabled']:
        raise ValueError('Unexpected compatibility frontend')
    if not config['outbounds'] or len(config['outbounds']) != len(inbound['users']):
        raise ValueError('Expected a distinct upstream for each account')
    inbound['listen_port'] = PORTS['entry'][0]
    for outbound in config['outbounds']:
        if (outbound['type'], outbound['server'], outbound['server_port']) != ('vless', '127.0.0.1', 46738):
            raise ValueError('Frontend must authenticate through the original VLESS inbound')
        if outbound.get('detour') or outbound.get('tls') or outbound.get('inet4_bind_address'):
            raise ValueError('Unexpected forwarded socket parameters')
        outbound['inet4_bind_address'] = SOURCE_IP
    return config


def command(args):
    result = subprocess.run(args, capture_output=True, timeout=35)
    if result.returncode:
        raise RuntimeError('Command failed: ' + Path(args[0]).name + ' ' + args[1])
    return result.stdout


def write_new(path, data, mode):
    with path.open('xb') as f:
        f.write(data)
    path.chmod(mode)


def unit_text(kind, folder, binary):
    credential = f'/run/credentials/vpn-failover-{kind}.service/config.json'
    params = ('run -config ' if kind == 'pool' else 'run -c ') + credential
    after = ' vpn-failover-pool.service' if kind == 'entry' else ''
    return f"""[Unit]
Description=Independent VPN failover {kind}
After=network-online.target{after}
Wants=network-online.target
[Service]
DynamicUser=yes
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
WorkingDirectory={folder}
Environment=XRAY_LOCATION_ASSET={folder}
LoadCredential=config.json:{ROOT / (kind + '.json')}
ExecStart={binary} {params}
Restart=on-failure
RestartSec=3
MemoryMax=256M
LimitNOFILE=65536
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def install(kind, config):
    unit = f'vpn-failover-{kind}.service'
    unit_path = Path('/etc/systemd/system') / unit
    folder = Path('/opt/vpn-failover') / kind
    path = ROOT / (kind + '.json')
    binary = folder / ('xray' if kind == 'pool' else 'sing-box')
    original = XRAY if kind == 'pool' else SING_BOX
    data = (json.dumps(config, indent=2) + '\n').encode()
    service_data = unit_text(kind, folder, binary).encode()
    if any(os.path.lexists(p) for p in (folder, path, unit_path)):
        if path.read_bytes() != data or unit_path.read_bytes() != service_data or not binary.is_file():
            raise RuntimeError('Different failover installation already exists; leaving it running')
        command(['systemctl', 'is-active', '--quiet', unit])
        print(unit + ' already active; no changes applied')
        return
    if command(['systemctl', 'show', unit, '-p', 'LoadState', '--value']).strip() != b'not-found':
        raise RuntimeError('Service name already in use')
    for port in PORTS[kind]:
        with socket.socket() as sock:
            sock.bind(('0.0.0.0' if kind == 'entry' else '127.0.0.1', port))
    ROOT.mkdir(mode=0o700, exist_ok=True)
    folder.parent.mkdir(mode=0o755, exist_ok=True)
    folder.parent.chmod(0o755)
    created = []
    try:
        folder.mkdir(mode=0o755)
        created.append(folder)
        folder.chmod(0o755)
        write_new(binary, original.read_bytes(), 0o755)
        if kind == 'pool':
            for filename in ('geoip.dat', 'geosite.dat'):
                write_new(folder / filename, (original.parent / filename).read_bytes(), 0o644)
        with tempfile.TemporaryDirectory(prefix='vpn-failover-check-') as temp:
            candidate = Path(temp) / 'config.json'
            write_new(candidate, data, 0o600)
            command((['env', 'XRAY_LOCATION_ASSET=' + str(folder), str(binary), 'run', '-test', '-config', str(candidate)]
                     if kind == 'pool' else [str(binary), 'check', '-c', str(candidate)]))
        write_new(path, data, 0o600)
        created.append(path)
        write_new(unit_path, service_data, 0o644)
        created.append(unit_path)
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'enable', '--now', unit])
        for attempt in range(20):
            try:
                for port in PORTS[kind]:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        pass
                break
            except OSError:
                if attempt == 19:
                    raise RuntimeError('New failover port did not come up')
                time.sleep(0.25)
        command(['systemctl', 'is-active', '--quiet', unit])
    except BaseException:
        if unit_path in created:
            subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True, timeout=20)
            state = command(['systemctl', 'show', unit, '-p', 'ActiveState', '--value']).strip()
            if state not in (b'inactive', b'failed'):
                raise RuntimeError('Failed to stop the new unit; retaining its files for inspection')
        for p in reversed(created):
            shutil.rmtree(p) if p.is_dir() else p.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=20)
        raise
    print(unit + ' started on ' + ','.join(map(str, PORTS[kind])))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render', 'install'])
    parser.add_argument('kind', choices=['pool', 'entry'])
    parser.add_argument('inventory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text())
    if args.kind == 'pool':
        config, names = build_pool(read(args.inventory)['failover'], read(MAIN), read(OLD_POOL),
                                   private_folder=args.inventory.parent/'outbounds')
        print('Failover priority: ' + ' -> '.join(names))
    else:
        config = build_entry(read(OLD_FRONTEND))
    if args.action == 'install':
        install(args.kind, config)
    else:
        if args.output is None:
            parser.error('--output is required for render')
        write_new(args.output, (json.dumps(config, indent=2) + '\n').encode(), 0o600)


if __name__ == '__main__':
    main()
