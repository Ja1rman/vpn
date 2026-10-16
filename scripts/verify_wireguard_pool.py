#!/usr/bin/env python3
"""Isolated WireGuard -> pool TCP/UDP canary with fresh disposable peer keys.

Never borrow a production WireGuard key: simultaneous use can move the real
peer's endpoint. Instead clone its protocol settings into an independent
loopback process; test the actual input's live route separately via routeTest.
Requires python3-cryptography on entry. Does not create kernel interfaces.
"""
import base64
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from activate_balancer import probe
from verify_vpn import udp_dns


def keypair():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    key = X25519PrivateKey.generate()
    return (base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
            base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    os.umask(0o077)
    main_config = json.loads(Path('/usr/local/x-ui/bin/config.json').read_text())
    inbound = copy.deepcopy(next(i for i in main_config['inbounds'] if i['tag'] == 'in-36307-udp'))
    server_key, server_public = keypair()
    client_key, client_public = keypair()
    wg_port, socks_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
    inbound.update(listen='127.0.0.1', port=wg_port)
    inbound['settings'].update(secretKey=server_key, noKernelTun=True,
                               peers=[{'publicKey': client_public, 'allowedIPs': ['10.0.0.2/32']}])
    pool = copy.deepcopy(next(o for o in main_config['outbounds'] if o['tag'] == 'vpn-egress-pool'))
    # Copy the ACTUAL rules selecting this inbound; no default pool route can
    # conceal a missing WG tag. An unmatched request is blackholed.
    rules = [r for r in main_config['routing']['rules']
             if inbound['tag'] in r.get('inboundTag', []) or r.get('outboundTag') == 'blocked']
    server = {'log': {'loglevel': 'warning'}, 'inbounds': [inbound],
              'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'}, pool],
              'routing': {'domainStrategy': main_config['routing']['domainStrategy'], 'rules': rules}}
    client = {'log': {'loglevel': 'warning'},
              'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                            'settings': {'auth': 'noauth', 'udp': True}}],
              'outbounds': [{'tag': 'wg-canary', 'protocol': 'wireguard',
                             'settings': {'secretKey': client_key, 'address': ['10.0.0.2/32'],
                                          'noKernelTun': True, 'mtu': inbound['settings'].get('mtu', 1420),
                                          'peers': [{'endpoint': '127.0.0.1:' + str(wg_port),
                                                     'publicKey': server_public,
                                                     'allowedIPs': ['0.0.0.0/0']} ]}}]}
    processes = []
    with tempfile.TemporaryDirectory(prefix='vpn-wg-canary-') as tmp:
        try:
            for name, config in [('server', server), ('client', client)]:
                path = Path(tmp) / (name + '.json')
                path.write_text(json.dumps(config))
                with (Path(tmp) / (name + '.log')).open('wb') as log:
                    processes.append(subprocess.Popen(['/usr/local/x-ui/bin/xray-linux-amd64', 'run', '-config', str(path)],
                                                       stdout=log, stderr=log,
                                                       env=dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/x-ui/bin')))
                time.sleep(0.5)
                if processes[-1].poll() is not None:
                    raise RuntimeError('Disposable WG ' + name + ' failed to start')
            ips = [probe('socks5h://127.0.0.1:' + str(socks_port)) for _ in range(4)]
            if ips != ['144.31.34.165'] * 4:
                raise RuntimeError('Unexpected isolated WireGuard exit')
            udp_dns(socks_port)
            print(json.dumps({'wireguard_isolated_tcp_exit_ips': ips, 'wireguard_isolated_udp_dns': 'passed',
                              'production_peer_keys_used': False, 'kernel_interfaces_created': False}))
        finally:
            for process in reversed(processes):
                process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    main()
