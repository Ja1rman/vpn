#!/usr/bin/env python3
"""Test a real backup in an isolated pool with a deliberately unreachable primary."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time

from verify_vpn import udp_dns


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-ip', required=True)
    parser.add_argument('--failed', type=int, default=1)
    parser.add_argument('--config',type=Path,default=Path('/etc/vpn-balancer/config.json'))
    args = parser.parse_args()
    config = copy.deepcopy(json.loads(args.config.read_text()))
    balancers = config['routing']['balancers']
    if not 1 <= args.failed < len(balancers):
        raise RuntimeError('Disable at least one exit and leave a reserve for the test')
    for balancer in balancers[:args.failed]:
        tag = balancer['selector'][0]
        primary = next(o for o in config['outbounds'] if o['tag'] == tag)
        if 'address' not in primary['settings'] or 'port' not in primary['settings']:
            raise RuntimeError('Unsupported outbound schema for isolated test')
        primary['settings'].update(address='127.0.0.1', port=free_port())
    socks_port = free_port()
    for inbound in config['inbounds']:
        inbound['port'] = socks_port if inbound['tag'] == 'pool-socks' else free_port()
        inbound['listen'] = '127.0.0.1'
    config['observatory']['probeInterval'] = '1s'
    config['log']['loglevel'] = 'info'
    with tempfile.TemporaryDirectory(prefix='vpn-real-backup-') as tmp:
        path = Path(tmp) / 'config.json'
        path.write_text(json.dumps(config))
        with (Path(tmp) / 'xray.log').open('wb') as log:
            process = subprocess.Popen(['/opt/vpn-balancer/xray', 'run', '-config', str(path)],
                                       env=dict(os.environ, XRAY_LOCATION_ASSET='/opt/vpn-balancer'),
                                       stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 40
            ips = []
            while time.monotonic() < deadline and len(ips) < 4:
                result = subprocess.run(['curl', '--fail', '--silent', '--max-time', '6', '--proxy',
                                         'socks5h://127.0.0.1:' + str(socks_port), 'https://api.ipify.org'],
                                        capture_output=True)
                if result.returncode == 0:
                    ip = result.stdout.decode().strip()
                    if ip != args.expected_ip:
                        raise RuntimeError('Unexpected backup exit IP')
                    ips.append(ip)
                else:
                    time.sleep(0.5)
            if len(ips) != 4:
                raise RuntimeError('Real backup did not become available')
            for _ in range(4):
                udp_dns(socks_port)
            print(json.dumps({'real_backup_isolated': 'passed', 'failed_exits_only_in_clone': args.failed,
                              'backup_exit_ips': ips, 'backup_udp_dns': '4 passed',
                              'production_config_untouched': True}))
        except Exception:
            destination=Path(tempfile.mkdtemp(prefix='backup-probe-',dir='/var/backups/vpn-infra'))
            shutil.copyfile(Path(tmp)/'xray.log',destination/'xray.log')
            print('Private failed-probe log retained at '+str(destination),flush=True)
            raise
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
