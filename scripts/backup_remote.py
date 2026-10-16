#!/usr/bin/env python3
"""Run as root remotely; stream a consistent x-ui/config backup to stdout."""
import glob
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

os.umask(0o077)
with tempfile.TemporaryDirectory(prefix="vpn-backup-") as tmp:
    snapshot = Path(tmp) / "x-ui.db"
    certs=[]
    if Path('/etc/x-ui/x-ui.db').exists():
        source = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
        destination = sqlite3.connect(snapshot)
        source.backup(destination)
        certs=[value for key,value in source.execute('SELECT key,value FROM settings') if key in {'webCertFile','webKeyFile','subCertFile','subKeyFile'} and value]
        destination.close()
        source.close()
    paths = ["/usr/local/x-ui/bin/config.json", "/usr/local/x-ui/x-ui.sh", "/etc/default/x-ui", "/usr/bin/x-ui", '/etc/vpn-balancer', '/etc/vpn-node', '/etc/vpn-exit', '/etc/vpn-monitoring', '/opt/vpn-infra/staging', '/root/.acme.sh']+certs
    def collect_cert_files(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in {'certificateFile','keyFile'} and isinstance(item,str):paths.append(item)
                else:collect_cert_files(item)
        elif isinstance(value,list):
            for item in value:collect_cert_files(item)
    if Path('/usr/local/x-ui/bin/config.json').exists():collect_cert_files(json.loads(Path('/usr/local/x-ui/bin/config.json').read_text()))
    for pattern in ["/etc/systemd/system/x-ui*", "/etc/systemd/system/vpn-*", "/etc/systemd/system/vk-turn*",
                    "/opt/vk-turn-proxy/*", "/etc/wireguard/*", "/etc/x-ui/*.env"]:
        paths.extend(glob.glob(pattern))
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as archive:
        if snapshot.exists():archive.add(snapshot, arcname="etc/x-ui/x-ui.db")
        for name in sorted(set(paths)):
            if Path(name).exists():
                archive.add(name, arcname=name.lstrip("/"))
        for name, command in {
            "systemd-x-ui.txt": ["systemctl", "cat", "x-ui"],
            "network-addresses.txt": ["ip", "-j", "address"],
            "network-routes.txt": ["ip", "-j", "route", "show", "table", "all"],
            "firewall.rules": ["iptables-save"],
            "xray-version.txt": ["/usr/local/x-ui/bin/xray-linux-amd64", "version"],
        }.items():
            try:result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            except FileNotFoundError:continue
            info = tarfile.TarInfo("inspection/" + name)
            info.size = len(result.stdout)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(result.stdout))
