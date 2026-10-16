#!/usr/bin/env python3
"""Root on entry: validate and hot-reload only Alertmanager, with rollback."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

CONFIG = Path('/etc/vpn-monitoring/alertmanager/alertmanager.yml')
CONTAINER = 'vpn-monitoring-alertmanager-1'


def pid():
    return subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Pid}}', CONTAINER]).strip()


def reload_config():
    request = urllib.request.Request('http://127.0.0.1:9093/-/reload', data=b'', method='POST')
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError('Alertmanager rejected reload')
    with urllib.request.urlopen('http://127.0.0.1:9093/-/ready', timeout=10) as response:
        if response.status != 200:
            raise RuntimeError('Alertmanager is not ready')


def private_copy(source, destination):
    shutil.copyfile(source, destination)
    os.chown(destination, 0, 65534)
    destination.chmod(0o640)


def main():
    os.umask(0o077)
    backup = Path('/var/backups/vpn-infra') / ('alertmanager-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(mode=0o700, parents=True)
    shutil.copyfile(CONFIG, backup / 'alertmanager.yml')
    before = pid()
    fd, name = tempfile.mkstemp(prefix='.candidate-', suffix='.yml', dir=CONFIG.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        private_copy(Path(sys.argv[1]), candidate)
        check = subprocess.run(['docker', 'exec', CONTAINER, 'amtool', 'check-config', str(candidate)],
                               capture_output=True, timeout=30)
        if check.returncode:
            raise RuntimeError('amtool rejected private configuration; original retained')
        os.replace(candidate, CONFIG)
        try:
            reload_config()
            if pid() != before:
                raise RuntimeError('Alertmanager PID changed unexpectedly')
        except BaseException:
            private_copy(backup / 'alertmanager.yml', candidate)
            os.replace(candidate, CONFIG)
            reload_config()
            raise
        print(json.dumps({'alertmanager_reload': 'passed', 'pid_unchanged': True,
                          'config_mode': oct(CONFIG.stat().st_mode & 0o777), 'rollback_directory': str(backup)}))
    finally:
        candidate.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
