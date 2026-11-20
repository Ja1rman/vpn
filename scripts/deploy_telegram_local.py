#!/usr/bin/env python3
"""Stage narrow Telegram routes and commit only after native external proof."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tempfile

import verify_telegram_proxy_clients as proof


ROOT = Path(__file__).resolve().parents[1]
HELPERS = ('enable_telegram_local.py', 'telegram_local_routes.py', 'enable_failover_variant.py')


def build_probe(output):
    """Compile the pinned official client locally, before arming any watchdog."""
    output = Path(output).resolve()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache = ROOT / '.local/telegram-probe/build-cache'
    modules = ROOT / '.local/telegram-probe/modules'
    environment = dict(os.environ, GOCACHE=str(cache), GOMODCACHE=str(modules), GOMAXPROCS='2')
    result = subprocess.run(['go', 'build', '-mod=readonly', '-p', '2', '-trimpath', '-o', str(output), '.'],
                            cwd=ROOT / 'tools/telegram-probe', env=environment,
                            capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError('Local pinned Telegram probe build failed')
    return output


def _backup(value):
    if not isinstance(value, str):
        raise RuntimeError('The armed transaction has no recovery directory')
    path = PurePosixPath(value)
    if (path.parent != PurePosixPath('/var/backups/vpn-infra')
            or not re.fullmatch(r'telegram-local-[0-9]{8}T[0-9]{12}Z', path.name)):
        raise RuntimeError('Unexpected Telegram recovery directory')
    return value


def deploy(options=None, *, verify_existing=False, controller=None):
    if controller is None:
        import vpnctl as controller
    options = options or proof.Options.defaults()
    if options.dd_access is None:
        raise RuntimeError('Deployment requires private DD credentials and native proof for all three routes')
    build_probe(options.gotd)
    prepared = proof.prepare(options)
    name = controller.inventory()['entry']['name']
    private = controller.ROOT / '.local'
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='telegram-local-', dir=private) as temporary:
        stage = controller.upload(name, Path(temporary), HELPERS)
        expected = '/opt/vpn-infra/staging/' + name + '/' + Path(temporary).name
        if stage != expected:
            raise RuntimeError('Unexpected private deployment staging directory')
        helper = stage + '/enable_telegram_local.py'
        backup = None
        committed = rolled_back = False

        def action(command, *arguments, data=None):
            result = controller.remote(name, 'sudo ' + shlex.join([
                'python3', '-B', helper, command, *arguments]), data=data, capture=True)
            return json.loads(result.stdout)

        try:
            applied = action('apply')
            if applied.get('armed') is True:
                backup = _backup(applied.get('backup'))
            elif applied.get('already_configured') is not True:
                raise RuntimeError('The Telegram installer returned no verified transaction state')
            if backup is None and not verify_existing:
                return {'already_configured': True, 'verified': False}
            result = proof.verify(options, prepared=prepared)
            success = (result.get('native_mtp') is True and result.get('native_socks') is True
                       and result.get('native_dd') is True
                       and result.get('temporary_clients_stopped') is True)
            if not success:
                if backup:
                    action('rollback', backup)
                    rolled_back = True
                raise RuntimeError('Native Telegram proof failed; the new transaction was rolled back')
            if backup:
                acknowledgement = {'native_mtp': True, 'native_socks': True, 'native_dd': True,
                                   'transaction': PurePosixPath(backup).name}
                confirmed = action('commit', backup, data=(json.dumps(acknowledgement) + '\n').encode())
                if confirmed.get('committed') is not True:
                    raise RuntimeError('Telegram transaction commit was not confirmed')
                committed = True
            return {'already_configured': backup is None, 'committed': committed,
                    'native_mtp': True, 'native_socks': True, 'native_dd': True, 'report': str(options.report)}
        except BaseException:
            if backup and not committed and not rolled_back:
                action('rollback', backup)
            raise
        finally:
            controller.remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    proof.add_arguments(parser)
    parser.add_argument('--verify-existing', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(deploy(proof.from_arguments(args), verify_existing=args.verify_existing)))
    except (OSError, RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'deploy-telegram-local: operation failed (' + type(error).__name__ + ')\n')


if __name__ == '__main__':
    main()
