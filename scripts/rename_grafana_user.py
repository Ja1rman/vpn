#!/usr/bin/env python3
"""Migrate the initial Grafana admin login; password is read only from a file."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import base64
import json
from pathlib import Path
import sys
import subprocess
import urllib.error
import urllib.request

stage=Path(sys.argv[1])
password=(stage/'grafana/admin-password').read_text().strip()
desired=(stage/'grafana/admin-user').read_text().strip()
installed=Path('/etc/vpn-monitoring/grafana/admin-user')
previous=installed.read_text().strip() if installed.exists() else 'admin'
logins=list(dict.fromkeys([desired,previous,'admin']))
for attempt,login in enumerate(logins+logins):
    if attempt==len(logins):
        subprocess.run(['docker','exec','-i','vpn-monitoring-grafana-1','grafana','cli','admin','reset-admin-password','--password-from-stdin'],input=(password+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    auth=base64.b64encode((login+':'+password).encode()).decode()
    request=urllib.request.Request(env_expand('http://${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}/api/user'),headers={'Authorization':'Basic '+auth})
    try:
        with urllib.request.urlopen(request,timeout=10) as response:user=json.load(response)
    except urllib.error.HTTPError as error:
        if error.code==401:continue
        raise
    if user['login']!=desired:
        request=urllib.request.Request(env_expand('http://${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}/api/user'),data=json.dumps({'login':desired,'email':user.get('email',''),'name':'VPN administrator'}).encode(),headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'},method='PUT')
        with urllib.request.urlopen(request,timeout=10) as response:json.load(response)
    print('Grafana login configured; credentials are not printed')
    break
else:raise RuntimeError('Unable to authenticate to Grafana with the stored credential')
