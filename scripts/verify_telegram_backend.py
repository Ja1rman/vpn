#!/usr/bin/env python3
"""Prove native SOCKS Telegram RPC on its own host without exporting credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from vpn_env import env, port


def authentication_digest(username, password):
    return hashlib.sha256(json.dumps({'username': username, 'password': password},
                                     sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(role, expected_digest, probe):
    if role == 'entry':
        value = json.loads(Path('/etc/vpn-telegram-socks/config.json').read_text())
        inbound = next(item for item in value['inbounds'] if item.get('tag') == 'telegram-socks')
        users = [(item['user'], item['pass']) for item in inbound['settings']['accounts']]
        number = port('VPN_TELEGRAM_SOCKS_PORT')
    elif role == 'nl':
        value = json.loads(Path('/etc/vpn-telegram-reserve/socks.json').read_text())
        users = [(item['username'], item['password']) for item in value['inbounds'][0]['users']]
        number = port('VPN_NL_TELEGRAM_SOCKS_PORT')
    else:
        raise RuntimeError('Choose a configured backend role')
    matches = [(user, password) for user, password in users
               if authentication_digest(user, password) == expected_digest]
    if len(matches) != 1:
        raise RuntimeError('The live backend credentials do not match the local client input')
    user, password = matches[0]
    with tempfile.TemporaryDirectory(prefix='vpn-telegram-backend-') as temporary:
        access = Path(temporary) / 'access.json'
        descriptor = os.open(access, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump({'server': env('VPN_LOOPBACK_IP'), 'port': number,
                       'username': user, 'password': password}, stream)
        result = subprocess.run([str(probe), '--mode', 'socks', '--access', str(access), '--dc', '2'],
                                capture_output=True, timeout=43)
        value = json.loads(result.stdout)
    success = (result.returncode == 0 and value.get('status') == 'passed'
               and value.get('account_login') is False and value.get('key_exchange') == 'passed'
               and value.get('rpc') == 'help.getNearestDC')
    return {'native_socks_backend': success, 'credentials_match_public_client': True,
            'credentials_exported': False, 'account_login': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['entry', 'nl'], required=True)
    parser.add_argument('--credentials-digest', required=True)
    parser.add_argument('--probe', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.role, args.credentials_digest, args.probe)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('The on-host Telegram backend proof failed; credentials were not logged') from None
    print(json.dumps(result))
    raise SystemExit(0 if result['native_socks_backend'] else 1)


if __name__ == '__main__':
    main()
