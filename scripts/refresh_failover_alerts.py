#!/usr/bin/env python3
"""Validate and hot-reload entry monitoring files without restarting containers or VPN."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
import urllib.request


ROOT = Path('/etc/vpn-monitoring')
BACKUPS = Path('/var/backups/vpn-infra')
ALERTMANAGER = 'alertmanager/alertmanager.yml'
FILES = ('blackbox.yml', 'prometheus/prometheus.yml', 'prometheus/alerts.yml',
         'prometheus/vpn-targets.json')
PORTS = {'blackbox': 9115, 'alertmanager': 9093, 'prometheus': 9090}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OLD_INHIBITION = (b"  - source_matchers: ['alertname=\"NodeUnavailable\"']\n"
                  b"    target_matchers: ['severity=\"warning\"']\n"
                  b"    equal: [host]\n")
NEW_INHIBITION = OLD_INHIBITION.replace(
    b"['severity=\"warning\"']",
    b"['severity=\"warning\"', 'alertname=~\"VpnPortUnavailable|HighCPU|HighMemory|DiskSpaceLow|HighNetworkTraffic\"']",
)


def merge_alertmanager(private_config):
    """Change only the known inhibition rule; retain every receiver and other setting."""
    if private_config.count(OLD_INHIBITION) == 1 and NEW_INHIBITION not in private_config:
        return private_config.replace(OLD_INHIBITION, NEW_INHIBITION, 1)
    if private_config.count(NEW_INHIBITION) == 1 and OLD_INHIBITION not in private_config:
        return private_config
    raise ValueError('Unexpected Alertmanager inhibition configuration; private file was not modified')


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Monitoring validation or inspection failed: ' + args[0])
    return result.stdout


def container(service):
    return f'vpn-monitoring-{service}-1'


def pid(service):
    value = int(docker('inspect', '--format', '{{.State.Pid}}', container(service)).strip())
    if value <= 1:
        raise RuntimeError(f'{service} is not running')
    return value


def request(service, path, post=False):
    url = f'http://127.0.0.1:{PORTS[service]}{path}'
    req = urllib.request.Request(url, data=b'' if post else None)
    with OPENER.open(req, timeout=8) as response:
        return response.read()


def prometheus_reload_state():
    data = request('prometheus', '/metrics')
    def metric(name):
        match = re.search(rb'(?m)^' + name + rb' ([^\r\n]+)$', data)
        if not match:
            raise RuntimeError('Prometheus reload metric missing')
        return float(match[1])
    return (metric(b'prometheus_config_last_reload_successful'),
            metric(b'prometheus_config_last_reload_success_timestamp_seconds'))


def reload_service(service, expected_pid):
    if pid(service) != expected_pid:
        raise RuntimeError(f'{service} PID changed before reload')
    if service == 'prometheus':
        _, old_stamp = prometheus_reload_state()
        # The installed Prometheus does not enable its lifecycle HTTP API.
        os.kill(expected_pid, signal.SIGHUP)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            good, stamp = prometheus_reload_state()
            if good == 1 and stamp > old_stamp:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Prometheus did not report a successful reload')
    else:
        request(service, '/-/reload', post=True)
    request(service, '/-/healthy' if service == 'blackbox' else '/-/ready')
    if pid(service) != expected_pid:
        raise RuntimeError(f'{service} PID changed during reload')


def read_regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f'Expected a regular file: {path.name}')
    return path.read_bytes(), info


def write_candidate(path, data, info):
    with path.open('xb') as output:
        output.write(data)
    os.chown(path, info.st_uid, info.st_gid)
    path.chmod(stat.S_IMODE(info.st_mode))


def validate_file_sd(data):
    groups = json.loads(data)
    if not isinstance(groups, list) or not groups or any(
        not isinstance(group, dict) or not isinstance(group.get('targets'), list)
        or not group['targets'] or any(not isinstance(t, str) or not t for t in group['targets'])
        or not isinstance(group.get('labels'), dict)
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in group['labels'].items())
        for group in groups
    ):
        raise ValueError('Invalid Prometheus file discovery targets')


def validate(candidates):
    docker('exec', container('blackbox'), '/bin/blackbox_exporter', '--config.check',
           f"--config.file={candidates['blackbox.yml']}")
    docker('exec', container('prometheus'), '/bin/promtool', 'check', 'rules',
           str(candidates['prometheus/alerts.yml']))
    docker('exec', container('prometheus'), '/bin/promtool', 'check', 'config',
           str(candidates['prometheus/prometheus.yml']))
    docker('exec', container('alertmanager'), 'amtool', 'check-config',
           str(candidates[ALERTMANAGER]))


def refresh(stage, apply, include_nodes):
    names = (*FILES, *(['prometheus/nodes.json'] if include_nodes else []), ALERTMANAGER)
    existing = {name: read_regular(ROOT / name) for name in names}
    proposed = {name: read_regular(stage / name)[0] for name in names if name != ALERTMANAGER}
    proposed[ALERTMANAGER] = merge_alertmanager(existing[ALERTMANAGER][0])
    for name in proposed:
        if name.endswith('.json'):
            validate_file_sd(proposed[name])
    pids = {service: pid(service) for service in PORTS}
    with tempfile.TemporaryDirectory(prefix='.failover-refresh-', dir=ROOT) as tmp:
        scratch = Path(tmp)
        # Containers need traversal; the private candidate keeps the live file's ownership/mode.
        scratch.chmod(0o755)
        candidates = {name: scratch / name.replace('/', '_') for name in names}
        for name in names:
            write_candidate(candidates[name], proposed[name], existing[name][1])
        validate(candidates)
        changed = [name for name in names if proposed[name] != existing[name][0]]
        if not apply or not changed:
            return {'validation': 'passed', 'applied': False, 'changed_files': changed}
        backup = BACKUPS / ('failover-monitoring-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(mode=0o700, parents=True)
        for name in changed:
            (backup / candidates[name].name).write_bytes(existing[name][0])
        affected = [service for service in PORTS if any(
            name == 'blackbox.yml' if service == 'blackbox' else
            name == ALERTMANAGER if service == 'alertmanager' else
            name.startswith('prometheus/') for name in changed)]
        installed = []
        try:
            for name in changed:
                if read_regular(ROOT / name)[0] != existing[name][0]:
                    raise RuntimeError('Live monitoring file changed concurrently: ' + name)
                os.replace(candidates[name], ROOT / name)
                installed.append(name)
            for service in affected:
                reload_service(service, pids[service])
            if any(pid(service) != old for service, old in pids.items()):
                raise RuntimeError('A monitoring process changed unexpectedly')
        except BaseException:
            failures = []
            for name in reversed(installed):
                try:
                    if read_regular(ROOT / name)[0] != proposed[name]:
                        raise RuntimeError('Concurrent modification')
                    recovery = scratch / ('rollback-' + candidates[name].name)
                    write_candidate(recovery, *existing[name])
                    os.replace(recovery, ROOT / name)
                except Exception:
                    failures.append(name)
            for service in affected:
                try:
                    reload_service(service, pids[service])
                except Exception:
                    failures.append(service)
            if failures:
                raise RuntimeError('Monitoring rollback needs inspection: ' + str(backup) +
                                   ' (' + ', '.join(failures) + ')') from None
            raise RuntimeError('Monitoring reload failed; previous files restored: ' + str(backup)) from None
    return {'validation': 'passed', 'applied': True, 'changed_files': changed,
            'unchanged_pids': pids, 'rollback_directory': str(backup)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', type=Path, help='staged monitoring tree (the payload directory)')
    parser.add_argument('--apply', action='store_true', help='install and reload after validation')
    parser.add_argument('--include-nodes', action='store_true', help='also update node exporter discovery')
    args = parser.parse_args()
    with Path('/run/lock/vpn-failover-monitoring.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(refresh(args.stage, args.apply, args.include_nodes)))


if __name__ == '__main__':
    main()
