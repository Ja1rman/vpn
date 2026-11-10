#!/usr/bin/env python3
"""Add an existing encrypted outbound or provision a new standalone exit."""
import argparse
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
from vpnctl import ROOT, inventory, remote, deploy_node, update_pool, update_failover_pool

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pool',choices=['legacy','auto'],default='legacy')
    p.add_argument('--name',required=True);p.add_argument('--address',required=True)
    p.add_argument('--user',default='root');p.add_argument('--interface',default='eth0')
    p.add_argument('--network-budget-mbps',type=int)
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--outbound',type=Path);source.add_argument('--provision',action='store_true')
    p.add_argument('--port',type=int,default=443);p.add_argument('--sni',default='api.github.com')
    args=p.parse_args();inv=inventory()
    if not re.fullmatch('[a-z][a-z0-9-]{0,40}',args.name):p.error('Invalid name')
    if not re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,31}',args.user):p.error('Invalid SSH user')
    try:ip=ipaddress.ip_address(args.address)
    except ValueError:p.error('Invalid IP address')
    args.address=str(ip)
    failover=inv.get('failover',{}).get('egresses',[])
    if any(n['name']==args.name for n in [inv['entry']]+inv['nodes']+failover):p.error('Name already exists')
    if not 1<=args.port<=65535 or (args.network_budget_mbps is not None and args.network_budget_mbps<=0):
        p.error('Invalid port or capacity')
    if args.pool=='legacy' and args.network_budget_mbps is None:
        p.error('--network-budget-mbps is required for the legacy pool')
    if args.pool=='auto':
        if len(args.name)>31:p.error('VPN Auto name must not exceed 31 characters')
        if not failover:p.error('VPN Auto must already be deployed')
        if not ip.is_global or any(n['address']==args.address for n in failover):
            p.error('VPN Auto needs a different public egress IP')
        if args.provision and ip.version!=4:p.error('Automatic provisioning requires a public IPv4 address')
    if not re.fullmatch('[a-zA-Z0-9.-]+',args.sni):p.error('Invalid SNI hostname')
    current=(ROOT/'inventory/hosts.json').read_bytes()
    filename=Path('.local/outbounds')/(args.name+'-vless.json')
    local=ROOT/filename
    if args.pool=='auto':
        if local.is_symlink() or (local.exists() and (args.outbound is None or args.outbound.resolve()!=local.resolve())):
            p.error('Private outbound file exists; use it explicitly with --outbound to retry')
        failover.append({'name':args.name,'address':args.address,'user':args.user,
                         'source':'file','file':filename.name})
    else:
        inv['nodes'].append({'name':args.name,'address':args.address,'user':args.user,
                             'interface':args.interface,'network_budget_mbps':args.network_budget_mbps,
                             'vpn_port':args.port,'outbounds':[str(filename)]})
    # Register for SSH lookup, restoring inventory if provisioning or validation fails.
    (ROOT/'inventory/hosts.json').write_text(json.dumps(inv,indent=2)+'\n')
    try:
        if args.provision:
            runtime=ROOT/'.local/runtime';runtime.mkdir(exist_ok=True)
            if not (runtime/'xray').exists():
                result=remote(inv['entry']['name'],'sudo tar czf - -C /opt/vpn-balancer xray geoip.dat geosite.dat',capture=True)
                with tarfile.open(fileobj=io.BytesIO(result.stdout),mode='r:gz') as archive:
                    for name in ['xray','geoip.dat','geosite.dat']:(runtime/name).write_bytes(archive.extractfile(name).read())
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:gz') as archive:
                for name in ['xray','geoip.dat','geosite.dat']:archive.add(runtime/name,arcname=name)
                archive.add(ROOT/'scripts/bootstrap_exit.py',arcname='bootstrap_exit.py')
            stage='/opt/vpn-infra/bootstrap'
            elevate='' if args.user=='root' else 'sudo -n '
            remote(args.name,f'{elevate}install -d -m 700 {stage} && {elevate}tar xzf - -C {stage}',stream.getvalue())
            result=remote(args.name,elevate+'python3 '+shlex.join([stage+'/bootstrap_exit.py',stage,args.address,str(args.port),args.sni]),capture=True)
            outbound=json.loads(result.stdout)
        else:outbound=json.loads(args.outbound.read_text())
        local.parent.mkdir(exist_ok=True)
        if args.pool=='auto':
            if not local.exists():
                with local.open('x') as target:
                    target.write(json.dumps(outbound,indent=2)+'\n')
            local.chmod(0o600)
            update_failover_pool()
        else:
            local.write_text(json.dumps(outbound,indent=2)+'\n')
            subprocess.run(['python3',str(ROOT/'scripts/render.py')],check=True)
            subprocess.run(['python3',str(ROOT/'scripts/certificates.py')],check=True)
            deploy_node(args.name)
            update_pool()
    except Exception:
        (ROOT/'inventory/hosts.json').write_bytes(current)
        print('Inventory restored. Any newly provisioned exit is left intact for inspection; existing VPN routes are unchanged.')
        raise
    print('Host added:',args.name)
    if args.pool=='legacy':
        print('Refresh Prometheus targets: python3 scripts/vpnctl.py deploy-monitoring')

if __name__=='__main__':main()
