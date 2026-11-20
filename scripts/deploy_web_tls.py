#!/usr/bin/env python3
"""Add trusted DNS TLS to the installed WEB relay without restarting VPN."""
import json
from pathlib import Path
import shlex
import shutil
import tempfile

import deploy_web_proxy
import vpnctl


def deploy():
    prepared = deploy_web_proxy.prepare(vpnctl)
    entry = vpnctl.inventory()['entry']['name']
    with tempfile.TemporaryDirectory(prefix='web-tls-', dir=vpnctl.ROOT / '.local') as temporary:
        folder = Path(temporary)
        shutil.copyfile(prepared['credentials'], folder / 'credentials.json')
        (folder / 'credentials.json').chmod(0o600)
        stage = vpnctl.upload(entry, folder, ['install_web_tls.py', 'install_web_proxy.py',
                                             'install_grafana_https.py'])
        try:
            result = vpnctl.remote(entry, 'sudo python3 -B ' + shlex.join([
                stage + '/install_web_tls.py', 'install', '--credentials',
                stage + '/payload/credentials.json']), capture=True)
            return json.loads(result.stdout)
        finally:
            vpnctl.remote(entry, 'sudo rm -rf -- ' + shlex.quote(stage))


if __name__ == '__main__':
    print(json.dumps(deploy()))
