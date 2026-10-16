#!/usr/bin/env python3
"""Hot-add pool outbounds and replace selectors, while retaining existing sessions."""
import json
from datetime import datetime, timezone
import fcntl
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from verify_vpn import udp_dns

XRAY='/opt/vpn-balancer/xray'
API='--server=127.0.0.1:11091'
CONFIG=Path('/etc/vpn-balancer/config.json')

def persist(config):
    staging=CONFIG.with_suffix('.json.new')
    staging.write_text(json.dumps(config,indent=2)+'\n')
    stat=CONFIG.stat();os.chown(staging,stat.st_uid,stat.st_gid);staging.chmod(0o640);staging.replace(CONFIG)

def rollback(folder):
    with (folder/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if (folder/'committed').exists() or (folder/'rolled-back').exists():return
        old=json.loads((folder/'before.json').read_text())
        desired=json.loads((folder/'after.json').read_text())
        if json.loads(CONFIG.read_text()) not in [old,desired]:
            raise RuntimeError('Concurrent pool config change; automatic rollback refused')
        subprocess.run([XRAY,'api','adrules',API,str(folder/'before.json')],check=True,timeout=15)
        persist(old)
        (folder/'rolled-back').write_text('Previous pool routing restored without restarting Xray\n')

def verify_singleton_candidates(config):
    balancers=config['routing'].get('balancers',[])
    if not balancers or not all(len(b['selector'])==1 for b in balancers):return
    for balancer in balancers:
        result=subprocess.check_output([XRAY,'api','bi',API,balancer['tag']],timeout=10).decode()
        if 'Selects:' not in result:raise RuntimeError('Cannot verify live priority candidates')
        selected=result.split('Selects:',1)[1]
        tags=re.findall(r'^\s*\d+\s+(\S+)\s*$',selected,re.MULTILINE)
        if tags!=balancer['selector']:
            raise RuntimeError('Priority selector also matched a retained runtime handler; use a distinct tag')

def probe_outbound(outbound,folder):
    canary={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':28200,'protocol':'socks','settings':{'auth':'noauth'}}], 'outbounds':[outbound]}
    path=folder/'canary.json';path.write_text(json.dumps(canary))
    log=(folder/'canary.log').open('wb')
    proc=subprocess.Popen([XRAY,'run','-config',str(path)],stdout=log,stderr=log,env=dict(os.environ,XRAY_LOCATION_ASSET='/opt/vpn-balancer'))
    try:
        time.sleep(1)
        subprocess.run(['curl','--fail','--silent','--show-error','--max-time','20','--proxy','socks5h://127.0.0.1:28200','https://www.google.com/generate_204'],stdout=subprocess.DEVNULL,check=True)
    finally:proc.terminate();proc.wait(timeout=10)

def main():
    os.umask(0o077)
    if len(sys.argv)>1 and sys.argv[1]=='watchdog':
        time.sleep(90);rollback(Path(sys.argv[2]));return
    desired=json.loads(Path(sys.argv[1]).read_text());old=json.loads(CONFIG.read_text())
    if old == desired:
        print('Pool configuration already matches; no changes applied');return
    for key in set(old)|set(desired):
        if key not in {'outbounds','routing'} and old.get(key)!=desired.get(key):raise RuntimeError(f'{key} requires a planned balancer restart; hot update refused')
    old_out={o['tag']:o for o in old['outbounds']};new_out={o['tag']:o for o in desired['outbounds']}
    for tag in old_out.keys() & new_out.keys():
        if old_out[tag]!=new_out[tag]:raise RuntimeError('Rename a modified node to stage new credentials without interrupting its existing sessions')
    additions=[o for tag,o in new_out.items() if tag not in old_out]
    backup=Path('/var/backups/vpn-infra')/('pool-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True,mode=0o700)
    (backup/'before.json').write_text(json.dumps(old,indent=2)+'\n')
    (backup/'after.json').write_text(json.dumps(desired,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='vpn-pool-update-') as tmp:
        folder=Path(tmp)
        candidate=folder/'candidate.json';candidate.write_text(json.dumps(desired))
        subprocess.run([XRAY,'run','-test','-config',str(candidate)],env=dict(os.environ,XRAY_LOCATION_ASSET='/opt/vpn-balancer'),check=True)
        for outbound in additions:
            # Native loopback bridges are validated as part of the whole config.
            # They cannot be meaningfully probed without their routing rules.
            if outbound.get('protocol')!='loopback':probe_outbound(outbound,folder)
        added=folder/'added.json';added.write_text(json.dumps({'outbounds':additions}))
        if additions:subprocess.run([XRAY,'api','ado',API,str(added)],check=True)
        with (backup/'watchdog.log').open('ab') as log:
            subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'watchdog',str(backup)],
                             stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        before_pid=subprocess.check_output(['systemctl','show','vpn-balancer','--property=MainPID','--value']).strip()
        try:
            subprocess.run([XRAY,'api','adrules',API,str(candidate)],check=True,timeout=15)
            verify_singleton_candidates(desired)
            # Keep removed handlers alive so established sessions can drain.
            persist(desired)
            subprocess.run(['curl','--fail','--silent','--show-error','--max-time','15','--proxy',
                            'socks5h://127.0.0.1:11090','https://www.google.com/generate_204'],
                           stdout=subprocess.DEVNULL,check=True)
            udp_dns(11090)
            if subprocess.check_output(['systemctl','show','vpn-balancer','--property=MainPID','--value']).strip()!=before_pid:
                raise RuntimeError('Balancer PID changed unexpectedly')
            with (backup/'lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                if (backup/'rolled-back').exists():raise RuntimeError('Watchdog already rolled back the update')
                (backup/'committed').write_text('TCP/UDP verified; balancer PID unchanged\n')
        except BaseException:
            rollback(backup)
            raise
        print('Pool updated without restart; added outbounds:',len(additions),'; backup:',str(backup))

if __name__=='__main__':main()
