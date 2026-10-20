#!/usr/bin/env python3
"""Provision a NEW standalone VLESS/REALITY exit. Does not modify existing x-ui."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid

def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)

def refuse_existing_exit():
    paths=[Path('/opt/vpn-exit'),Path('/etc/vpn-exit')]
    paths += [Path(base)/'vpn-exit.service' for base in
              ['/etc/systemd/system','/run/systemd/system','/lib/systemd/system','/usr/lib/systemd/system']]
    paths += [Path('/etc/systemd/system/vpn-exit.service.d'),
              Path('/etc/systemd/system/multi-user.target.wants/vpn-exit.service')]
    if any(os.path.lexists(path) for path in paths):
        raise RuntimeError('Standalone exit path or unit already exists; refusing to overwrite')
    result=run('systemctl','show','vpn-exit.service','-p','LoadState','--value',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.stdout.decode().strip()!='not-found':
        raise RuntimeError('Standalone exit unit already registered; refusing to overwrite')

def main():
    os.umask(0o077)
    stage=Path(sys.argv[1]);address=sys.argv[2];port=int(sys.argv[3]);sni=sys.argv[4]
    refuse_existing_exit()
    check=socket.socket()
    try:check.bind(('0.0.0.0',port))
    finally:check.close()
    runtime=Path('/opt/vpn-exit');dest=Path('/etc/vpn-exit');unit=Path('/etc/systemd/system/vpn-exit.service')
    created_files=[];created_dirs=[];unit_started=False
    try:
        runtime.mkdir(mode=0o755);created_dirs.append(runtime)
        # mkdir modes are filtered by umask 077; the service user needs traversal.
        runtime.chmod(0o755)
        for filename in ['xray','geoip.dat','geosite.dat']:
            path=runtime/filename
            with (stage/filename).open('rb') as source,path.open('xb') as output:
                created_files.append(path)
                shutil.copyfileobj(source,output)
            path.chmod(0o755 if filename=='xray' else 0o644)
        keys=run(str(runtime/'xray'),'x25519',stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.decode()
        parsed={re.sub('[^a-z]','',k.lower()):v.strip() for line in keys.splitlines() if ':' in line for k,v in [line.split(':',1)]}
        private=parsed['privatekey'];public=parsed.get('passwordpublickey') or parsed.get('password') or parsed.get('publickey')
        if not public:raise RuntimeError('Unknown x25519 output format')
        uid=str(uuid.uuid4());short=secrets.token_hex(8)
        configure_exit(runtime,dest,unit,address,port,sni,private,uid,short,created_files,created_dirs)
        run('systemctl','daemon-reload',stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        unit_started=True
        run('systemctl','enable','--now','vpn-exit',stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(3):
            time.sleep(.5)
            run('systemctl','is-active','--quiet','vpn-exit',stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    except Exception:
        # These paths were all absent at preflight and created exclusively by this call.
        # Never stop x-ui or remove any pre-existing installation.
        if unit_started:
            subprocess.run(['systemctl','disable','--now','vpn-exit.service'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if subprocess.run(['systemctl','is-active','--quiet','vpn-exit.service'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE).returncode==0:
                raise RuntimeError('New standalone exit failed; could not stop its service, leaving new files for inspection') from None
        cleanup_errors=[]
        for path in reversed(created_files):
            try:path.unlink(missing_ok=True)
            except OSError:cleanup_errors.append(str(path))
        for path in reversed(created_dirs):
            try:path.rmdir()
            except FileNotFoundError:pass
            except OSError:cleanup_errors.append(str(path))
        if unit in created_files:
            subprocess.run(['systemctl','daemon-reload'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            subprocess.run(['systemctl','reset-failed','vpn-exit.service'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        raise RuntimeError('New standalone exit installation failed; new files/service cleaned up'+
                           ('; inspect remaining paths: '+', '.join(cleanup_errors) if cleanup_errors else '')) from None
    # Caller captures this JSON into a private local file, never prints credentials.
    print(json.dumps({'protocol':'vless','settings':{'address':address,'port':port,'id':uid,'encryption':'none','flow':'xtls-rprx-vision'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':sni,'fingerprint':'chrome','publicKey':public,'shortId':short,'spiderX':'/'}}}))

def configure_exit(runtime,dest,unit,address,port,sni,private,uid,short,created_files,created_dirs):
    config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'vpn-exit','listen':'0.0.0.0','port':port,'protocol':'vless','settings':{'clients':[{'id':uid,'flow':'xtls-rprx-vision'}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'target':sni+':443','serverNames':[sni],'privateKey':private,'shortIds':[short]}}}], 'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'finalRules':[{'action':'block','ip':['geoip:private']},{'action':'allow'}]}},{'tag':'blocked','protocol':'blackhole'}], 'routing':{'rules':[{'type':'field','ip':['geoip:private'],'outboundTag':'blocked'},{'type':'field','protocol':['bittorrent'],'outboundTag':'blocked'}]}}
    run('groupadd','--system','vpn-exit',stdout=subprocess.DEVNULL) if subprocess.run(['getent','group','vpn-exit'],stdout=subprocess.DEVNULL).returncode else None
    if subprocess.run(['id','vpn-exit'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:run('useradd','--system','--gid','vpn-exit','--no-create-home','--shell','/usr/sbin/nologin','vpn-exit')
    dest.mkdir(mode=0o750);created_dirs.append(dest);dest.chmod(0o750)
    conf=dest/'config.json'
    with conf.open('x') as handle:
        created_files.append(conf)
        handle.write(json.dumps(config,indent=2))
    conf.chmod(0o640)
    shutil.chown(dest,group='vpn-exit');shutil.chown(conf,group='vpn-exit')
    env=dict(os.environ,XRAY_LOCATION_ASSET=str(runtime))
    run('runuser','--user','vpn-exit','--',str(runtime/'xray'),'run','-test','-config',str(conf),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    with unit.open('x') as handle:
        created_files.append(unit)
        handle.write('[Unit]\nDescription=VLESS REALITY VPN exit\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=vpn-exit\nGroup=vpn-exit\nWorkingDirectory=/opt/vpn-exit\nEnvironment=XRAY_LOCATION_ASSET=/opt/vpn-exit\nExecStart=/opt/vpn-exit/xray run -config /etc/vpn-exit/config.json\nRestart=always\nRestartSec=2\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nUMask=0077\nMemoryMax=512M\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n')
    unit.chmod(0o644)

if __name__=='__main__':main()
