#!/usr/bin/env python3
"""SSH deployment helper. Uses host key verification; never modifies back."""
import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]
INVENTORY=ROOT/'inventory/hosts.json'

def inventory():return json.loads(INVENTORY.read_text())

def node(name):
    inv=inventory()
    standalone=[n for n in inv.get('failover',{}).get('egresses',[]) if n.get('source')=='file' and 'user' in n]
    return next(n for n in [inv['entry']]+inv['nodes']+standalone if n['name']==name)

def ssh_args(name):
    n=node(name)
    args=['ssh','-o',f'UserKnownHostsFile={ROOT}/.local/ssh/known_hosts','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=4','-o','ControlMaster=auto','-o',f'ControlPath={ROOT}/.local/ssh/%C','-o','ControlPersist=600',f'{n["user"]}@{n["address"]}']
    password=ROOT/'.local/ssh'/f'{name}.password'
    # Legacy local filename retained for the initial Netherlands credential.
    if name=='breeze-reef' and not password.exists():password=ROOT/'.local/ssh/nl.password'
    if password.exists():args=['sshpass','-f',str(password)]+args
    return args

def remote(name,command,data=None,capture=False):
    return subprocess.run(ssh_args(name)+[command],input=data,check=True,stdout=subprocess.PIPE if capture else None)

def upload(name,folder,extras=()):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as archive:
        archive.add(folder,arcname='payload')
        for filename in extras:archive.add(ROOT/'scripts'/filename,arcname=filename)
    stage='/opt/vpn-infra/staging/'+name+'/'+folder.name
    remote(name,f'sudo install -d -m 700 {stage} && sudo tar xzf - -C {stage}',stream.getvalue())
    return stage

def backup(name):
    output=ROOT/'.local/backups'/f'{name}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.tar.gz'
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('wb') as file:
        subprocess.run(ssh_args(name)+['sudo python3 -'],input=(ROOT/'scripts/backup_remote.py').read_bytes(),stdout=file,check=True)
    print(output)

def deploy_node(name):
    n=node(name); inv=inventory();release=json.loads((ROOT/'monitoring/releases.json').read_text())['node_exporter']
    stage=upload(name,ROOT/'.local/rendered/nodes'/name,['install_node.sh'])
    address='127.0.0.1' if name==inv['entry']['name'] else '0.0.0.0'
    remote(name,'sudo bash '+shlex.join([stage+'/install_node.sh',stage+'/payload',f'{address}:{inv["monitoring"]["node_port"]}',release['version'],release['sha256_linux_amd64']]))

def deploy_monitoring():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring',['install_monitoring.sh','rename_grafana_user.py'])
    # Fresh installations have no existing account to migrate.
    remote(name,'if curl -fsS http://127.0.0.1:3000/api/health >/dev/null 2>&1; then sudo python3 '+shlex.join([stage+'/rename_grafana_user.py',stage+'/payload'])+'; fi')
    remote(name,'sudo bash '+shlex.join([stage+'/install_monitoring.sh',stage+'/payload']))

def refresh_grafana():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring',['refresh_grafana.sh','rename_grafana_user.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/rename_grafana_user.py',stage+'/payload']))
    remote(name,'sudo bash '+shlex.join([stage+'/refresh_grafana.sh',stage+'/payload']))

def deploy_vpn_usage():
    import shutil
    import tempfile

    name = inventory()['entry']['name']
    private = ROOT / '.local'
    with tempfile.TemporaryDirectory(prefix='vpn-usage-', dir=private) as tmp:
        folder = Path(tmp)
        monitoring = ROOT / 'monitoring'
        for unit in ('vpn-usage-collector.service', 'vpn-usage-collector.timer'):
            shutil.copyfile(monitoring / 'usage' / unit, folder / unit)
        shutil.copyfile(monitoring / 'grafana/dashboards/vpn-usage.json', folder / 'vpn-usage.json')
        mapping = private / 'vpn-usage-devices.json'
        if mapping.is_file():
            shutil.copyfile(mapping, folder / 'devices.json')
        stage = upload(name, folder, ['install_vpn_usage.sh', 'vpn_usage_collector.py'])
        try:
            remote(name, 'sudo bash ' + shlex.join([stage + '/install_vpn_usage.sh', stage]))
        finally:
            remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))

def refresh_alertmanager():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring/alertmanager',['refresh_alertmanager.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/refresh_alertmanager.py',stage+'/payload/alertmanager.yml']))

def deploy_balancer():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/balancer',['install_balancer.sh'])
    remote(name,'sudo bash '+shlex.join([stage+'/install_balancer.sh',stage+'/payload']))

def activate_balancer():
    name=inventory()['entry']['name']
    folder=ROOT/'.local/activation';folder.mkdir(exist_ok=True)
    stage=upload(name,folder,['panel.py','activate_balancer.py'])
    remote(name,'sudo python3 '+shlex.quote(stage+'/activate_balancer.py'))

def migrate_direct_inbounds():
    name=inventory()['entry']['name']
    folder=ROOT/'.local/route-migration';folder.mkdir(exist_ok=True)
    stage=upload(name,folder,['panel.py','activate_balancer.py','verify_vpn.py','migrate_direct_inbounds.py'])
    remote(name,'sudo python3 '+shlex.quote(stage+'/migrate_direct_inbounds.py'))

def update_pool():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/balancer',['update_pool.py','verify_vpn.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/update_pool.py',stage+'/payload/config.json']))

def deploy_compatible():
    from compatible_vless import VERSION, ARCHIVE_SHA256
    import hashlib
    import shutil
    archive=ROOT/'.local/compatible-vless'/f'sing-box-{VERSION}-linux-amd64.tar.gz'
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest()!=ARCHIVE_SHA256:
        raise RuntimeError('Place the pinned official sing-box archive in .local/compatible-vless first')
    folder=ROOT/'.local/rendered/compatible-vless-bootstrap'
    folder.mkdir(parents=True,mode=0o700,exist_ok=True)
    shutil.copyfile(archive,folder/archive.name)
    stage=upload(inventory()['entry']['name'],folder,['compatible_vless.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/compatible_vless.py','install','--archive',stage+'/payload/'+archive.name]))

def publish_compatible():
    folder=ROOT/'.local/compatible-publication';folder.mkdir(mode=0o700,exist_ok=True)
    stage=upload(inventory()['entry']['name'],folder,['compatible_profiles.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/compatible_profiles.py','publish','--address',inventory()['entry']['address']]))

def refresh_probes():
    stage=upload(inventory()['entry']['name'],ROOT/'.local/rendered/monitoring/prometheus',['refresh_probe_targets.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/refresh_probe_targets.py',stage+'/payload/vpn-targets.json']))

def stage_failover():
    from failover_variant import private_outbound_file
    import tempfile
    raw=INVENTORY.read_bytes()
    inv=json.loads(raw)
    with tempfile.TemporaryDirectory(prefix='failover-deploy-',dir=ROOT/'.local') as tmp:
        folder=Path(tmp)
        (folder/'hosts.json').write_bytes(raw)
        for entry in inv['failover']['egresses']:
            if entry['source']=='file':
                filename=private_outbound_file(entry)
                source=ROOT/'.local/outbounds'/filename
                if source.is_symlink() or not source.is_file():
                    raise ValueError('Missing private outbound: '+filename)
                (folder/'outbounds').mkdir(mode=0o700,exist_ok=True)
                (folder/'outbounds'/filename).write_bytes(source.read_bytes())
        return upload(inv['entry']['name'],folder,[
            'failover_variant.py','priority_pool.py','verify_priority_backup.py','verify_vpn.py',
            'enable_failover_variant.py','failover_subscription.py','install_failover_subscription.py',
            'update_failover_pool.py','auto_ru_routes.py','enable_auto_ru.py'])

def update_failover_pool():
    stage=stage_failover()
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/update_failover_pool.py',stage+'/payload/hosts.json']))

def refresh_failover_monitoring():
    import shutil
    folder=ROOT/'.local/failover-monitoring'
    (folder/'prometheus').mkdir(parents=True,mode=0o700,exist_ok=True)
    for name in ('blackbox.yml','prometheus/prometheus.yml','prometheus/alerts.yml','prometheus/vpn-targets.json'):
        shutil.copyfile(ROOT/'.local/rendered/monitoring'/name,folder/name)
    stage=upload(inventory()['entry']['name'],folder,['refresh_failover_alerts.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/refresh_failover_alerts.py',stage+'/payload','--apply']))

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['backup','deploy-node','deploy-monitoring','refresh-grafana','deploy-vpn-usage','refresh-alertmanager','refresh-probes','deploy-balancer','activate-balancer','migrate-direct-inbounds','update-pool','update-failover-pool','deploy-compatible','publish-compatible','stage-failover','refresh-failover-monitoring','ssh','tunnel'])
    parser.add_argument('name',nargs='?',default='entry')
    args=parser.parse_args()
    if args.command=='backup':backup(args.name)
    elif args.command=='deploy-node':deploy_node(args.name)
    elif args.command=='deploy-monitoring':deploy_monitoring()
    elif args.command=='refresh-grafana':refresh_grafana()
    elif args.command=='deploy-vpn-usage':deploy_vpn_usage()
    elif args.command=='refresh-alertmanager':refresh_alertmanager()
    elif args.command=='deploy-balancer':deploy_balancer()
    elif args.command=='activate-balancer':activate_balancer()
    elif args.command=='migrate-direct-inbounds':migrate_direct_inbounds()
    elif args.command=='update-pool':update_pool()
    elif args.command=='deploy-compatible':deploy_compatible()
    elif args.command=='publish-compatible':publish_compatible()
    elif args.command=='refresh-probes':refresh_probes()
    elif args.command=='stage-failover':print(stage_failover())
    elif args.command=='update-failover-pool':update_failover_pool()
    elif args.command=='refresh-failover-monitoring':refresh_failover_monitoring()
    elif args.command=='ssh':subprocess.run(ssh_args(args.name),check=True)
    elif args.command=='tunnel':
        cmd=ssh_args(inventory()['entry']['name'])
        cmd[-1:-1]=['-N','-o','ExitOnForwardFailure=yes','-L','127.0.0.1:3000:127.0.0.1:3000','-L','127.0.0.1:9090:127.0.0.1:9090','-L','127.0.0.1:9093:127.0.0.1:9093']
        subprocess.run(cmd,check=True)

if __name__=='__main__':main()
