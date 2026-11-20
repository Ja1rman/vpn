#!/usr/bin/env python3
"""Add an existing encrypted outbound or provision a new standalone exit."""
import argparse
import copy
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
from vpn_env import configured_values, load_json, port
from vpnctl import ROOT, remote, deploy_node, update_pool, update_failover_pool


def inventory_addition(template, args, filename):
    """Keep public inventory symbolic; actual endpoints belong to the private registry."""
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}', args.name):
        raise ValueError('Invalid new host name')
    prefix = 'VPN_HOST_' + args.name.upper().replace('-', '_')
    address_name, port_name = prefix + '_ADDRESS', prefix + '_PORT'
    host = {'name': args.name, 'address': '${' + address_name + '}', 'user': args.user}
    candidate = copy.deepcopy(template)
    if args.pool == 'auto':
        host.update(source='file', file=filename.name)
        candidate['failover']['egresses'].append(host)
    else:
        host.update(interface=args.interface, network_budget_mbps=args.network_budget_mbps,
                    vpn_port='${' + port_name + '}', outbounds=[str(filename)])
        candidate['nodes'].append(host)
    return candidate, {address_name: args.address, port_name: args.port}


def write_atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='.' + path.name + '-', dir=path.parent, delete=False) as target:
        temporary = Path(target.name)
        try:
            os.fchmod(target.fileno(), mode)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def private_network_candidate(path, updates):
    if path.is_symlink():
        raise ValueError('The private network registry must not be a symlink')
    values = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(values, dict):
        raise ValueError('The private network registry must be a JSON object')
    for name, value in updates.items():
        if name in values and str(values[name]) != str(value):
            raise ValueError('A different private endpoint already uses ' + name)
    values.update(updates)
    return (json.dumps(values, indent=2) + '\n').encode()

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pool',choices=['legacy','auto'],default='legacy')
    p.add_argument('--name',required=True);p.add_argument('--address',required=True)
    p.add_argument('--user',default='root');p.add_argument('--interface',default='eth0')
    p.add_argument('--network-budget-mbps',type=int)
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--outbound',type=Path);source.add_argument('--provision',action='store_true')
    p.add_argument('--port',type=int);p.add_argument('--sni',default='api.github.com')
    args=p.parse_args();inv=load_json(ROOT/'inventory/hosts.json')
    if args.port is None:args.port=port('VPN_EXIT_TLS_PORT')
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
    template=json.loads(current)
    registry=ROOT/'.local/network-env.json'
    network_before=registry.read_bytes() if registry.exists() else None
    filename=Path('.local/outbounds')/(args.name+'-vless.json')
    local=ROOT/filename
    if args.pool=='auto':
        if local.is_symlink() or (local.exists() and (args.outbound is None or args.outbound.resolve()!=local.resolve())):
            p.error('Private outbound file exists; use it explicitly with --outbound to retry')
    candidate,endpoint_updates=inventory_addition(template,args,filename)
    configured=configured_values()
    for name,value in endpoint_updates.items():
        if name in configured and str(configured[name])!=str(value):
            p.error('A different deployment endpoint already uses '+name)
    network_after=private_network_candidate(registry,endpoint_updates)
    inventory_after=(json.dumps(candidate,indent=2)+'\n').encode()
    # Register for SSH lookup, restoring inventory if provisioning or validation fails.
    try:
        write_atomic(registry,network_after)
        write_atomic(ROOT/'inventory/hosts.json',inventory_after)
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
                archive.add(ROOT/'scripts/vpn_env.py',arcname='vpn_env.py')
                network=json.dumps(configured_values()).encode()
                info=tarfile.TarInfo('vpn.env.json');info.size=len(network);info.mode=0o600
                archive.addfile(info,io.BytesIO(network))
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
        inventory_path=ROOT/'inventory/hosts.json'
        if inventory_path.read_bytes()==inventory_after:
            write_atomic(inventory_path,current)
        if registry.exists() and registry.read_bytes()==network_after:
            if network_before is None:registry.unlink()
            else:write_atomic(registry,network_before)
        print('Local registration restored. Any newly provisioned exit is left intact for inspection; existing VPN routes are unchanged.')
        raise
    print('Host added:',args.name)
    if args.pool=='legacy':
        print('Refresh Prometheus targets: python3 scripts/vpnctl.py deploy-monitoring')

if __name__=='__main__':main()
