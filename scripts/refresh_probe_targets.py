#!/usr/bin/env python3
"""Update Prometheus file_sd TCP targets atomically without restarting services."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys


def main():
    os.umask(0o077)
    candidate = Path(sys.argv[1]).read_bytes()
    groups = json.loads(candidate)
    if not isinstance(groups, list) or not groups or any(
            not isinstance(g, dict) or not isinstance(g.get('targets'), list)
            or not g['targets'] or any(not isinstance(t, str) or not t for t in g['targets'])
            or not isinstance(g.get('labels'), dict) for g in groups):
        raise ValueError('Invalid TCP probe file_sd target groups')
    target = Path('/etc/vpn-monitoring/prometheus/vpn-targets.json')
    if json.loads(target.read_bytes()) == groups:
        print('TCP probe targets already match; no changes applied')
        return
    backup = Path('/var/backups/vpn-infra') / (
        'probe-targets-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    backup.write_bytes(target.read_bytes())
    staging = target.with_suffix('.json.new')
    staging.write_bytes(candidate)
    staging.chmod(0o644)
    staging.replace(target)
    print('Prometheus file_sd targets updated; no restart; backup: ' + str(backup))


if __name__ == '__main__':
    main()
