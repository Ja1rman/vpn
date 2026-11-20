#!/usr/bin/env python3
"""Verify both Telegram proxies through a real Auto profile without account login."""
import argparse
import concurrent.futures
import copy
from dataclasses import dataclass
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from uuid import UUID

from vpn_env import env, port


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/telegram-probe'
NEKOBOX_AGENT = 'NekoBox/Android/1.4.2 (Prefer ClashMeta Format)'
MAX_BODY = 128 * 1024


@dataclass(frozen=True)
class Options:
    sing_box: Path
    gotd: Path
    subscriptions: Path
    mtproto_access: Path
    socks_access: Path
    report: Path
    dc_config: Path | None = None
    interface: str | None = None
    dc: int = 2
    dd_access: Path | None = None

    @classmethod
    def defaults(cls):
        current = PRIVATE / 'dcs.json'
        dd = ROOT / '.local/mtproto-dd/access.json'
        return cls(PRIVATE / 'sing-box', PRIVATE / 'telegram-probe', PRIVATE / 'subscription.json',
                   ROOT / '.local/mtproto/access.json', ROOT / '.local/telegram-socks/access.json',
                   PRIVATE / 'report.json', current if current.is_file() else None,
                   os.environ.get('VPN_TELEGRAM_PROBE_INTERFACE') or None,
                   dd_access=dd if dd.is_file() else None)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def private_json(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 512 * 1024,
            'Use a small owner-only regular JSON file for private probe inputs')
    return json.loads(path.read_text())


def write_private(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.is_symlink(), 'Refusing a symlink for a private probe output')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')


def subscription_ids(path):
    value = private_json(path)
    require(isinstance(value, dict), 'Expected private subscription JSON')
    values = [value['sub_id']] if 'sub_id' in value else [row.get('sub_id') for row in value.get('clients', [])]
    require(values and len(values) <= 64 and all(isinstance(value, str) and
            re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) for value in values),
            'Private subscription JSON must contain sub_id or clients with sub_id')
    return list(dict.fromkeys(values))


def fetch_profile(sub_id):
    address = env('VPN_ENTRY_ADDRESS')
    connection = http.client.HTTPSConnection(address, port('VPN_AUTO_SUBSCRIPTION_PORT'),
                                             context=ssl.create_default_context(), timeout=6)
    try:
        connection.request('GET', '/sub/' + sub_id, headers={
            'User-Agent': NEKOBOX_AGENT, 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        if response.status == 404:
            return None
        require(response.status == 200 and response.getheader('Content-Encoding', 'identity') == 'identity',
                'The Auto subscription did not return its normal response')
        body = response.read(MAX_BODY + 1)
    finally:
        connection.close()
    require(0 < len(body) <= MAX_BODY, 'Unexpected Auto subscription response size')
    value = json.loads(body)
    require(isinstance(value, dict) and set(value) == {'outbounds'} and len(value['outbounds']) == 1,
            'Expected one actual NekoBox Auto outbound')
    profile = value['outbounds'][0]
    require(isinstance(profile, dict) and isinstance(profile.get('tag'), str) and profile['tag'],
            'The Auto profile has no stable display name')
    uid = str(UUID(profile.get('uuid')))
    expected = {'type': 'vless', 'tag': profile['tag'], 'server': address,
                'server_port': port('VPN_AUTO_TLS_PUBLIC_PORT'), 'uuid': uid, 'packet_encoding': 'xudp',
                'multiplex': {'enabled': False}, 'tls': {'enabled': True, 'server_name': address,
                'insecure': False, 'utls': {'enabled': True, 'fingerprint': 'chrome'}}}
    require(profile == expected, 'The Auto profile differs from verified TLS, authorization or MUX settings')
    return profile


def prepare(options):
    for executable in (options.sing_box, options.gotd):
        require(executable.is_file() and os.access(executable, os.X_OK), 'Prepare both local client binaries first')
    if options.interface:
        socket.if_nametoindex(options.interface)
    require(1 <= options.dc <= 5, 'Unsupported Telegram data center')
    accesses = [
            (options.mtproto_access, 'VPN_MTPROTO_PUBLIC_PORT', ('secret',)),
            (options.socks_access, 'VPN_TELEGRAM_SOCKS_PORT', ('username', 'password'))]
    if options.dd_access:
        accesses.append((options.dd_access, 'VPN_MTPROTO_DD_PORT', ('secret',)))
    for path, endpoint, fields in accesses:
        value = private_json(path)
        require(isinstance(value, dict) and value.get('server') == env('VPN_ENTRY_ADDRESS')
                and value.get('port') == port(endpoint)
                and all(isinstance(value.get(key), str) and value[key] for key in fields),
                'Private access input does not match the entry proxy being verified')
    if options.dc_config:
        require(isinstance(private_json(options.dc_config), list), 'Expected private Telegram DC options')
    for identifier in subscription_ids(options.subscriptions):
        profile = fetch_profile(identifier)
        if profile is not None:
            return {'sub_id': identifier, 'profile': profile}
    raise RuntimeError('No active NekoBox Auto profile was available')


def client_command(options, mode, access, dc_config=None, save_dcs=None):
    private_access = {'mtproto': options.mtproto_access, 'socks': options.socks_access, 'dd': options.dd_access}[mode]
    require(private_access is not None, 'Prepare private DD credentials before requesting DD proof')
    protocol = 'mtproto' if mode == 'dd' else mode
    command = [str(options.gotd.resolve()), '--mode', protocol, '--access', str(private_access.resolve()),
               '--dc', str(options.dc), '--via-socks', str(access)]
    if dc_config:
        command += ['--dc-config', str(dc_config)]
    if save_dcs:
        command += ['--save-dcs', str(save_dcs)]
    return command


def native_client(options, mode, access, dc_config=None, save_dcs=None):
    try:
        result = subprocess.run(client_command(options, mode, access, dc_config, save_dcs),
                                capture_output=True, timeout=60)
        value = json.loads(result.stdout)
        passed = (result.returncode == 0 and value.get('status') == 'passed'
                  and value.get('key_exchange') == 'passed' and value.get('rpc') == 'help.getNearestDC'
                  and value.get('nested_via_auto') is True and value.get('account_login') is False)
        # Never echo arbitrary child output, endpoints, identifiers or error text.
        row = {'mode': mode, 'status': 'passed' if passed else 'failed',
               'key_exchange': passed, 'anonymous_rpc': passed}
        if isinstance(value.get('elapsed_ms'), int):
            row['elapsed_ms'] = value['elapsed_ms']
        return mode, passed, row
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        return mode, False, {'mode': mode, 'status': 'failed', 'error_type': type(error).__name__}


def verify(options, prepared=None):
    prepared = prepared or prepare(options)
    profile = fetch_profile(prepared['sub_id'])
    require(profile == prepared['profile'], 'The actual Auto profile changed after preflight')
    loopback = env('VPN_LOOPBACK_IP')
    with socket.socket() as reserve:
        reserve.bind((loopback, 0))
        local_port = reserve.getsockname()[1]
    username, password = secrets.token_hex(10), secrets.token_hex(24)
    outbound = copy.deepcopy(profile)
    if options.interface:
        outbound['bind_interface'] = options.interface
    config = {'log': {'disabled': True}, 'inbounds': [{'type': 'socks', 'tag': 'probe',
              'listen': loopback, 'listen_port': local_port,
              'users': [{'username': username, 'password': password}]}],
              'outbounds': [outbound], 'route': {'final': outbound['tag']}}
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='clients-', dir=PRIVATE) as directory:
        folder = Path(directory)
        configuration, access = folder / 'client.json', folder / 'local-socks.json'
        write_private(configuration, config)
        write_private(access, {'server': loopback, 'port': local_port, 'username': username, 'password': password})
        checked = subprocess.run([str(options.sing_box.resolve()), 'check', '-c', str(configuration)],
                                 capture_output=True, timeout=8)
        require(checked.returncode == 0, 'The isolated Auto client configuration did not compile')
        process = subprocess.Popen([str(options.sing_box.resolve()), 'run', '-c', str(configuration)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                require(process.poll() is None, 'The isolated Auto client stopped')
                try:
                    with socket.create_connection((loopback, local_port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('The isolated Auto client did not start')
            modes = ('mtproto', 'socks', 'dd') if options.dd_access else ('mtproto', 'socks')
            if options.dc_config:
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(modes)) as pool:
                    rows = list(pool.map(lambda mode: native_client(options, mode, access, options.dc_config),
                                         modes))
            else:
                # Obtain current DCs through MTProxy instead of relying on stale SDK bootstrap IPs.
                current = folder / 'dcs.json'
                mtproto = native_client(options, 'mtproto', access, save_dcs=current)
                if mtproto[1]:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=len(modes) - 1) as pool:
                        remaining = list(pool.map(lambda mode: native_client(options, mode, access, current), modes[1:]))
                else:
                    remaining = [(mode, False, {'mode': mode, 'status': 'skipped_after_mtproto_failure'})
                                 for mode in modes[1:]]
                rows = [mtproto, *remaining]
            checks = {mode: passed for mode, passed, _row in rows}
            report = {'native_mtp': checks['mtproto'], 'native_socks': checks['socks'],
                      'native_dd': checks.get('dd', False),
                      'actual_nekobox_auto_profile': True, 'interface': options.interface,
                      'account_login': False, 'checks': [row for _mode, _passed, row in rows]}
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        report['temporary_clients_stopped'] = process.poll() is not None
    write_private(options.report, report)
    return report


def add_arguments(parser):
    defaults = Options.defaults()
    for flag in ('sing_box', 'gotd', 'subscriptions', 'mtproto_access', 'socks_access', 'dd_access', 'report', 'dc_config'):
        parser.add_argument('--' + flag.replace('_', '-'), type=Path, default=getattr(defaults, flag))
    parser.add_argument('--interface', default=defaults.interface,
                        help='Optional physical interface for the local Auto core; OS routes are otherwise used')
    parser.add_argument('--dc', type=int, default=defaults.dc)


def from_arguments(args):
    return Options(**{field: getattr(args, field) for field in Options.__dataclass_fields__})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    args = parser.parse_args()
    try:
        report = verify(from_arguments(args))
        print(json.dumps(report))
        required = report['native_mtp'] and report['native_socks'] and report['temporary_clients_stopped']
        return 0 if required and (not args.dd_access or report['native_dd']) else 1
    except (OSError, ValueError, TypeError, RuntimeError, http.client.HTTPException,
            subprocess.SubprocessError) as error:
        parser.exit(1, 'telegram-client-proof: operation failed (' + type(error).__name__ + ')\n')


if __name__ == '__main__':
    raise SystemExit(main())
