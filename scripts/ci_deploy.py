#!/usr/bin/env python3
"""Manual GitHub Actions deployment to existing servers. Not a bootstrap."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

from ci_environment import ROOT, hydrate, write_private
import vpnctl


def server_backup(name, stamp):
    directory = '/var/backups/vpn-infra/ci/' + stamp
    command = ('umask 077; install -d -m 700 ' + shlex.quote(directory) +
               '; python3 - > ' + shlex.quote(directory + '/configuration.tar.gz'))
    vpnctl.remote(name, 'sudo sh -ec ' + shlex.quote(command),
                  (ROOT / 'scripts/backup_remote.py').read_bytes())
    print('Private server backup retained on ' + name + ': ' + directory, flush=True)


def main():
    os.umask(0o077)
    if os.environ.get('VPN_DEPLOY_ENABLED') != 'true':
        raise ValueError('Deployment is disabled by VPN_DEPLOY_ENABLED')
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('This entry point requires a manual Actions run from main')
    component = os.environ.get('VPN_DEPLOY_COMPONENT', '')
    if component not in {'dashboards', 'pool', 'monitoring', 'node-exporters', 'all'}:
        raise ValueError('Unknown deployment component')
    inv, hosts = hydrate()
    subprocess.run([sys.executable, str(ROOT / 'scripts/render.py')], check=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/certificates.py')], check=True)
    if os.environ.get('VPN_ALERTMANAGER_CONFIG'):
        write_private(ROOT / '.local/rendered/monitoring/alertmanager/alertmanager.yml',
                      os.environ['VPN_ALERTMANAGER_CONFIG'])
    run = os.environ.get('GITHUB_RUN_ID', '') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[0-9]+-[0-9]+', run):
        raise ValueError('Missing Actions run identifier')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + run
    targets = hosts if component in {'node-exporters', 'all'} else [inv['entry']]
    for host in targets:
        server_backup(host['name'], stamp)
    if component in {'node-exporters', 'all'}:
        for host in hosts:
            vpnctl.deploy_node(host['name'])
    if component in {'monitoring', 'all'}:
        vpnctl.deploy_monitoring()
    if component == 'dashboards':
        vpnctl.refresh_grafana()
    if component in {'pool', 'all'}:
        vpnctl.update_pool()
    print('Deployment completed: ' + component)


if __name__ == '__main__':
    main()
