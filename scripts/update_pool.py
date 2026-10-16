#!/usr/bin/env python3
"""Hot-add pool outbounds and replace selectors, while retaining existing sessions."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

XRAY='/opt/vpn-balancer/xray'
API='--server=127.0.0.1:11091'
CONFIG=Path('/etc/vpn-balancer/config.json')

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
    desired=json.loads(Path(sys.argv[1]).read_text());old=json.loads(CONFIG.read_text())
    for key in set(old)|set(desired):
        if key not in {'outbounds','routing'} and old.get(key)!=desired.get(key):raise RuntimeError(f'{key} requires a planned balancer restart; hot update refused')
    old_out={o['tag']:o for o in old['outbounds']};new_out={o['tag']:o for o in desired['outbounds']}
    for tag in old_out.keys() & new_out.keys():
        if old_out[tag]!=new_out[tag]:raise RuntimeError('Rename a modified node to stage new credentials without interrupting its existing sessions')
    additions=[o for tag,o in new_out.items() if tag not in old_out]
    with tempfile.TemporaryDirectory(prefix='vpn-pool-update-') as tmp:
        folder=Path(tmp)
        candidate=folder/'candidate.json';candidate.write_text(json.dumps(desired))
        subprocess.run([XRAY,'run','-test','-config',str(candidate)],env=dict(os.environ,XRAY_LOCATION_ASSET='/opt/vpn-balancer'),check=True)
        for outbound in additions:probe_outbound(outbound,folder)
        added=folder/'added.json';added.write_text(json.dumps({'outbounds':additions}))
        if additions:subprocess.run([XRAY,'api','ado',API,str(added)],check=True)
        try:
            subprocess.run([XRAY,'api','adrules',API,str(candidate)],check=True)
        except Exception:
            previous=folder/'old.json';previous.write_text(json.dumps(old))
            subprocess.run([XRAY,'api','adrules',API,str(previous)],check=True)
            raise
        # Keep removed handlers alive until process restart, so existing sessions can drain.
        staging=CONFIG.with_suffix('.json.new');staging.write_text(json.dumps(desired,indent=2)+'\n')
        stat=CONFIG.stat();os.chown(staging,stat.st_uid,stat.st_gid);staging.chmod(0o640);staging.replace(CONFIG)
        print('Pool updated without restart; added outbounds:',len(additions))

if __name__=='__main__':main()
