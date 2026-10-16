#!/usr/bin/env python3
"""Apply only outbound/routing changes through x-ui, with detached rollback."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from panel import Panel

XRAY='/usr/local/x-ui/bin/xray-linux-amd64'
CONFIG=Path('/usr/local/x-ui/bin/config.json')

def xray_pids():
    result=[]
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            args=path.read_bytes().split(b'\0')
            if args and args[0]==b'bin/xray-linux-amd64':result.append(int(path.parent.name))
        except (PermissionError,FileNotFoundError,ProcessLookupError):pass
    return sorted(result)

def probe(proxy, account=None):
    config='proxy = '+json.dumps(proxy)+'\n'
    if account:config+='proxy-user = '+json.dumps(account['user']+':'+account['pass'])+'\n'
    run=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','20','--config','-','https://api.ipify.org'],input=config.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return run.stdout.decode().strip()

def change_template(old, legacy_tags, port):
    new=copy.deepcopy(old)
    outbound={'tag':'vpn-egress-pool','protocol':'socks','settings':{'address':'127.0.0.1','port':port}}
    existing=[o for o in new['outbounds'] if o['tag']=='vpn-egress-pool']
    if existing and existing[0]!=outbound:raise ValueError('Conflicting vpn-egress-pool outbound')
    if not existing:new['outbounds'].append(outbound)
    count=0
    for rule in new['routing']['rules']:
        if rule.get('outboundTag') in legacy_tags:
            rule['outboundTag']='vpn-egress-pool';count+=1
    return new,count

def watchdog(folder):
    time.sleep(90)
    if (folder/'committed').exists():return
    p=Panel()
    try:p.save(json.loads((folder/'template-before.json').read_text()))
    finally:p.close()
    (folder/'rolled-back').write_text('Automatic template rollback completed\n')

def main():
    os.umask(0o077)
    if len(sys.argv)>1 and sys.argv[1]=='watchdog':
        watchdog(Path(sys.argv[2]));return
    if len(sys.argv)>1 and sys.argv[1]=='rollback':
        folder=Path(sys.argv[2]);p=Panel()
        try:p.save(json.loads((folder/'template-before.json').read_text()))
        finally:p.close()
        print('Previous routing restored through x-ui API');return
    p=Panel()
    old=p.template();running=json.loads(CONFIG.read_text())
    legacy=[o['tag'] for o in old['outbounds'] if o.get('protocol') in {'vless','hysteria'}]
    new,count=change_template(old,legacy,11090)
    if count==0:
        p.close()
        print('No legacy routes to change; current pool configuration is retained');return
    folder=Path('/var/backups/vpn-infra')/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder.mkdir(parents=True,mode=0o700)
    (folder/'template-before.json').write_text(json.dumps(old))
    candidate=copy.deepcopy(running)
    candidate['outbounds']=new['outbounds']
    candidate['routing']=copy.deepcopy(new['routing'])
    for rule in candidate['routing']['rules']:rule.pop('enabled',None)
    candidate_path=folder/'candidate.json';candidate_path.write_text(json.dumps(candidate))
    env=dict(os.environ,XRAY_LOCATION_ASSET='/usr/local/x-ui/bin')
    subprocess.run([XRAY,'run','-test','-config',str(candidate_path)],env=env,check=True)
    before=xray_pids()
    expected=probe('socks5h://127.0.0.1:11090')
    if not expected:raise RuntimeError('Pool egress check failed')
    log=(folder/'watchdog.log').open('ab')
    subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'watchdog',str(folder)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    try:
        p.save(new)
        time.sleep(2)
        after=xray_pids()
        if before!=after:raise RuntimeError('Main Xray unexpectedly restarted')
        updated=json.loads(CONFIG.read_text())
        if running['inbounds']!=updated['inbounds']:raise RuntimeError('Existing inbounds changed')
        # Test the existing authenticated HTTP inbound, including the main core.
        http=next(i for i in updated['inbounds'] if i['protocol']=='http' and any(i['tag'] in r.get('inboundTag',[]) and r.get('outboundTag')=='vpn-egress-pool' for r in updated['routing']['rules']))
        account=next(iter(http['settings'].get('accounts',[])),None)
        observed=probe('http://127.0.0.1:'+str(http['port']),account)
        if observed!=expected:raise RuntimeError('Unexpected main VPN exit address')
        (folder/'committed').write_text('Validated; main Xray PID unchanged; inbounds unchanged\n')
        print(json.dumps({'changed_routes':count,'main_xray_pids':after,'inbounds_unchanged':True,'exit_ip':observed,'rollback_directory':str(folder)}))
    except Exception:
        p.save(old)
        (folder/'committed').write_text('Immediate rollback completed\n')
        raise
    finally:p.close()

if __name__=='__main__':main()
