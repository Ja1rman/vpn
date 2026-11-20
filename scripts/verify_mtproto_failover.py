#!/usr/bin/env python3
"""Verify MTProto through isolated Auto pool/mtg copies; never change live services."""
import argparse
from contextlib import ExitStack
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


POOL_CONFIG = Path('/etc/vpn-failover/pool.json')
MTG_CONFIG = Path('/etc/vpn-mtproto/config.toml')
XRAY = Path('/opt/vpn-failover/pool/xray')
MTG = Path('/opt/vpn-mtproto/mtg')
SERVICES = ('x-ui.service', 'vpn-balancer.service', 'vpn-failover-pool.service',
            'vpn-failover-entry.service', 'vpn-mtproto.service')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def reserve_port(stack):
    sock = stack.enter_context(socket.socket())
    sock.bind(('127.0.0.1', 0))
    return sock, sock.getsockname()[1]


def isolated_pool(original, failed, ports, dead_ports):
    config = copy.deepcopy(original)
    inbounds = {item['tag']: item for item in config['inbounds']}
    need(len(inbounds) == len(config['inbounds']) and
         {'pool-socks', 'api'} <= set(inbounds) <= {'pool-socks', 'api', 'pool-ip-sniff'},
         'Unsupported Auto listener configuration')
    need(set(ports) == set(inbounds), 'Incomplete isolated listener mapping')
    for tag, inbound in inbounds.items():
        need(inbound.get('listen') == '127.0.0.1', 'Expected existing loopback-only Auto listeners')
        inbound.update(listen='127.0.0.1', port=ports[tag])
    balances = config['routing']['balancers']
    need(len(balances) == 3 and 1 <= failed <= 3 and len(dead_ports) == failed,
         'Expected a three-exit priority pool and one to three failures')
    outbounds = {item['tag']: item for item in config['outbounds']}
    need(len(outbounds) == len(config['outbounds']), 'Duplicate Auto outbound tags')
    selectors = []
    for balancer in balances:
        selector = balancer['selector']
        need(len(selector) == 1 and selector[0].startswith('pool-site-'),
             'Expected a single encrypted site on each priority step')
        need(selector[0] in outbounds and selector[0] not in selectors,
             'Invalid Auto priority selectors')
        outbound = outbounds[selector[0]]
        need(outbound['protocol'] == 'vless' and
             outbound.get('streamSettings', {}).get('security') in ('tls', 'reality'),
             'Expected encrypted VLESS Auto sites')
        selectors.append(selector[0])
    for tag, port in zip(selectors[:failed], dead_ports):
        settings = outbounds[tag]['settings']
        if 'address' in settings:
            endpoint = settings
        else:
            need(len(settings.get('vnext', [])) == 1, 'Unsupported VLESS endpoint format')
            endpoint = settings['vnext'][0]
        endpoint.update(address='127.0.0.1', port=port)
    for outbound in config['outbounds']:
        if outbound['tag'] == 'vpn-auto-sniff-hop':
            need('pool-ip-sniff' in ports and outbound['protocol'] == 'socks' and
                 outbound['settings'].get('address') == '127.0.0.1', 'Unsupported Auto inspection hop')
            outbound['settings']['port'] = ports['pool-ip-sniff']
    config['observatory']['probeInterval'] = '1s'
    config['log'] = {'loglevel': 'warning', 'access': 'none'}
    return config


def isolated_mtg(source, mtg_port, socks_port):
    """Rewrite only two generated one-line settings; preserve every other line.

    This intentionally accepts only the installer's simple double-quoted format,
    so Python 3.10 needs neither a general TOML writer nor a third-party parser.
    """
    need('"""' not in source and "'''" not in source, 'Multiline TOML strings are not supported')
    section, replacements, lines = '', {'bind-to': 0, 'proxies': 0}, []
    for line in source.splitlines(keepends=True):
        header = re.fullmatch(r'\s*\[([^\[\]]+)\]\s*(?:#.*)?', line.strip())
        if header:
            section = header[1].strip()
        if not section and re.match(r'^\s*bind-to\s*=', line):
            match = re.fullmatch(r'\s*bind-to\s*=\s*("[^"\\\r\n]*")\s*(?:#.*)?', line.strip())
            need(match is not None and isinstance(json.loads(match[1]), str),
                 'Expected a generated single-line MTProto listener')
            line = 'bind-to = ' + json.dumps('127.0.0.1:' + str(mtg_port)) + '\n'
            replacements['bind-to'] += 1
        elif section == 'network' and re.match(r'^\s*proxies\s*=', line):
            match = re.fullmatch(r'\s*proxies\s*=\s*(\[[^\r\n]*\])\s*(?:#.*)?', line.strip())
            need(match is not None,
                 'Expected a single-line SOCKS proxy list')
            need(json.loads(match[1]) == ['socks5://127.0.0.1:11092'],
                 'MTProto must use only the existing Auto SOCKS proxy')
            line = 'proxies = [' + json.dumps('socks5://127.0.0.1:' + str(socks_port)) + ']\n'
            replacements['proxies'] += 1
        lines.append(line)
    need(replacements == {'bind-to': 1, 'proxies': 1}, 'Could not isolate both MTProto settings')
    return ''.join(lines)


def snapshot(paths):
    files = {}
    for path in paths:
        info = path.stat()
        files[str(path)] = {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                            'size': info.st_size, 'mtime_ns': info.st_mtime_ns,
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    pids = {}
    for service in SERVICES:
        result = subprocess.run(['systemctl', 'show', service, '-p', 'MainPID', '--value'],
                                capture_output=True, text=True, timeout=5, check=True)
        need(result.stdout.strip().isdigit() and int(result.stdout.strip()) > 0,
             'A required live service has no active PID')
        pids[service] = int(result.stdout.strip())
    return {'files': files, 'pids': pids}


def stop_owned(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_listener(port, process, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        need(process.poll() is None, 'An isolated test process exited early')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('An isolated listener did not start')


def https_exit(port, timeout=5):
    result = subprocess.run(['curl', '--fail', '--silent', '--connect-timeout', '2',
                             '--max-time', str(timeout), '--proxy', 'socks5h://127.0.0.1:' + str(port),
                             'https://api.ipify.org'], capture_output=True, timeout=timeout+2)
    if result.returncode:
        return None
    try:
        return str(ipaddress.ip_address(result.stdout.decode().strip()))
    except ValueError:
        raise RuntimeError('The isolated HTTPS response was not an IP address') from None


def write_private(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(content)


def verify(args):
    need(args.client.is_file(), 'Sibling MTProto verifier is not available yet')
    original = snapshot((args.pool_config, args.mtg_config, args.xray, args.mtg))
    report = {'failed_sites_only_in_clone': args.failed}
    with tempfile.TemporaryDirectory(prefix='vpn-mtproto-failover-') as tmp, ExitStack() as stack:
        folder = Path(tmp)
        pool_source = json.loads(args.pool_config.read_text())
        reserves = {item['tag']: reserve_port(stack) for item in pool_source['inbounds']}
        dead_ports = [reserve_port(stack)[1] for _ in range(args.failed)]
        mtg_socket, mtg_port = reserve_port(stack)
        ports = {tag: entry[1] for tag, entry in reserves.items()}
        pool = isolated_pool(pool_source, args.failed, ports, dead_ports)
        pool_path, mtg_path = folder/'pool.json', folder/'mtg.toml'
        write_private(pool_path, json.dumps(pool))
        write_private(mtg_path, isolated_mtg(args.mtg_config.read_text(), mtg_port, ports['pool-socks']))
        env = dict(os.environ, XRAY_LOCATION_ASSET=str(args.xray.parent))
        processes = []
        error = None
        try:
            check = subprocess.run([str(args.xray), 'run', '-test', '-config', str(pool_path)],
                                   env=env, capture_output=True, timeout=15)
            need(check.returncode == 0, 'Isolated pool configuration validation failed')
            for sock, _ in reserves.values():
                sock.close()
            pool_log = stack.enter_context((folder/'xray.log').open('wb'))
            process = subprocess.Popen([str(args.xray), 'run', '-config', str(pool_path)],
                                       env=env, stdout=pool_log, stderr=pool_log, start_new_session=True)
            processes.append(process)
            wait_listener(ports['pool-socks'], process)
            if args.failed < 3:
                deadline = time.monotonic()+40
                while time.monotonic() < deadline:
                    need(process.poll() is None, 'The isolated pool exited during its HTTPS probe')
                    current = https_exit(ports['pool-socks'], timeout=min(5, max(1, deadline-time.monotonic())))
                    if current == args.expected_ip:
                        report['isolated_https_exit'] = current
                        break
                    need(current is None, 'Isolated HTTPS used an unexpected exit')
                    time.sleep(0.3)
                else:
                    raise RuntimeError('The expected backup did not serve isolated HTTPS within 40 seconds')
            else:
                # Allow the 1-second observatory to mark all loopback failures before the negative probe.
                time.sleep(3)
                need(https_exit(ports['pool-socks']) is None, 'All-failed pool unexpectedly had an HTTPS exit')
                report['isolated_https_blocked'] = True
            mtg_socket.close()
            mtg_log = stack.enter_context((folder/'mtg.log').open('wb'))
            process = subprocess.Popen([str(args.mtg), 'run', str(mtg_path)],
                                       stdout=mtg_log, stderr=mtg_log, start_new_session=True)
            processes.append(process)
            wait_listener(mtg_port, process, timeout=15)
            result = subprocess.run([sys.executable, str(args.client), '--host', '127.0.0.1',
                                     '--port', str(mtg_port), '--config', str(mtg_path), '--dc', '2'],
                                    capture_output=True, text=True, timeout=30)
            need(all(child.poll() is None for child in processes),
                 'An isolated process exited during the MTProto RPC')
            write_private(folder/'client.stdout', result.stdout)
            write_private(folder/'client.stderr', result.stderr)
            try:
                client = json.loads(result.stdout)
            except ValueError:
                raise RuntimeError('The MTProto verifier returned no structured result') from None
            if args.failed == 3:
                need(result.returncode != 0, 'All-failed pool unexpectedly completed the MTProto RPC')
                # A malformed test runner or cryptography setup must not count as fail-closed proof.
                need(client.get('stage') == 'mtproto_rpc' and client.get('fake_tls') is True,
                     'The negative MTProto probe did not fail at the expected RPC stage')
                report['mtproto_rpc_blocked'] = True
            else:
                need(result.returncode == 0 and client.get('fake_tls') is True and
                     client.get('nonce_verified') is True, 'MTProto did not complete the real Telegram RPC')
                report['mtproto_rpc'] = {key: client[key] for key in ('fake_tls', 'nonce_verified', 'dc', 'rpc_ms')
                                        if key in client}
        except BaseException as exc:
            error = exc
        finally:
            for process in reversed(processes):
                try:
                    stop_owned(process)
                except BaseException as exc:
                    error = error or exc
            try:
                need(snapshot((args.pool_config, args.mtg_config, args.xray, args.mtg)) == original,
                     'A protected production file or service PID changed during the test')
                report['production_files_and_pids_unchanged'] = True
            except BaseException as exc:
                error = error or exc
            if error is not None:
                args.diagnostics.mkdir(parents=True, mode=0o700, exist_ok=True)
                destination = Path(tempfile.mkdtemp(prefix='mtproto-failover-', dir=args.diagnostics))
                for path in folder.iterdir():
                    if path.is_file():
                        shutil.copyfile(path, destination/path.name)
                        (destination/path.name).chmod(0o600)
                print(json.dumps({'status': 'failed', 'private_diagnostics': str(destination)}), flush=True)
        if error is not None:
            raise error
    report['temporary_processes_stopped'] = True
    return report


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--failed', type=int, choices=(1, 2, 3), default=2)
    parser.add_argument('--expected-ip', type=lambda value: str(ipaddress.ip_address(value)))
    parser.add_argument('--pool-config', type=Path, default=POOL_CONFIG)
    parser.add_argument('--mtg-config', type=Path, default=MTG_CONFIG)
    parser.add_argument('--xray', type=Path, default=XRAY)
    parser.add_argument('--mtg', type=Path, default=MTG)
    parser.add_argument('--client', type=Path, default=Path(__file__).with_name('verify_mtproto.py'))
    parser.add_argument('--diagnostics', type=Path, default=Path('/var/backups/vpn-infra'))
    args = parser.parse_args()
    if args.failed < 3 and not args.expected_ip:
        parser.error('--expected-ip is required when at least one exit remains')
    def interrupted(signum, frame):
        raise InterruptedError('Verification was interrupted')
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        print(json.dumps(verify(args)))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print(json.dumps({'status': 'failed', 'error': message}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
