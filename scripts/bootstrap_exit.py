#!/usr/bin/env python3
"""Provision a NEW standalone VLESS/REALITY exit. Does not modify existing x-ui."""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import uuid

def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)

def main():
    os.umask(0o077)
    stage=Path(sys.argv[1]);address=sys.argv[2];port=int(sys.argv[3]);sni=sys.argv[4]
    if Path('/etc/vpn-exit/config.json').exists():raise RuntimeError('Exit already provisioned; refusing to rotate existing keys')
    check=socket.socket()
    try:check.bind(('0.0.0.0',port))
    finally:check.close()
    runtime=Path('/opt/vpn-exit');runtime.mkdir(mode=0o755,exist_ok=True)
    for filename in ['xray','geoip.dat','geosite.dat']:
        shutil.copyfile(stage/filename,runtime/filename)
        (runtime/filename).chmod(0o755 if filename=='xray' else 0o644)
    keys=run(str(runtime/'xray'),'x25519',stdout=subprocess.PIPE).stdout.decode()
    parsed={k.strip().lower().replace(' ',''):v.strip() for line in keys.splitlines() if ':' in line for k,v in [line.split(':',1)]}
    private=parsed['privatekey'];public=parsed.get('password',parsed.get('publickey'))
    if not public:raise RuntimeError('Unknown x25519 output format')
    uid=str(uuid.uuid4());short=secrets.token_hex(8)
    config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'vpn-exit','listen':'0.0.0.0','port':port,'protocol':'vless','settings':{'clients':[{'id':uid,'flow':'xtls-rprx-vision'}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'target':sni+':443','serverNames':[sni],'privateKey':private,'shortIds':[short]}}}], 'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'finalRules':[{'action':'block','ip':['geoip:private']},{'action':'allow'}]}},{'tag':'blocked','protocol':'blackhole'}], 'routing':{'rules':[{'type':'field','ip':['geoip:private'],'outboundTag':'blocked'},{'type':'field','protocol':['bittorrent'],'outboundTag':'blocked'}]}}
    run('groupadd','--system','vpn-exit',stdout=subprocess.DEVNULL) if subprocess.run(['getent','group','vpn-exit'],stdout=subprocess.DEVNULL).returncode else None
    if subprocess.run(['id','vpn-exit'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:run('useradd','--system','--gid','vpn-exit','--no-create-home','--shell','/usr/sbin/nologin','vpn-exit')
    dest=Path('/etc/vpn-exit');dest.mkdir(mode=0o750)
    conf=dest/'config.json';conf.write_text(json.dumps(config,indent=2));conf.chmod(0o640)
    shutil.chown(dest,group='vpn-exit');shutil.chown(conf,group='vpn-exit')
    env=dict(os.environ,XRAY_LOCATION_ASSET=str(runtime))
    run(str(runtime/'xray'),'run','-test','-config',str(conf),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    Path('/etc/systemd/system/vpn-exit.service').write_text('[Unit]\nDescription=VLESS REALITY VPN exit\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=vpn-exit\nGroup=vpn-exit\nWorkingDirectory=/opt/vpn-exit\nEnvironment=XRAY_LOCATION_ASSET=/opt/vpn-exit\nExecStart=/opt/vpn-exit/xray run -config /etc/vpn-exit/config.json\nRestart=always\nRestartSec=2\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nMemoryMax=512M\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl','daemon-reload',stdout=subprocess.DEVNULL)
    run('systemctl','enable','--now','vpn-exit',stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    run('systemctl','is-active','--quiet','vpn-exit')
    # Caller captures this JSON into a private local file, never prints credentials.
    print(json.dumps({'protocol':'vless','settings':{'address':address,'port':port,'id':uid,'encryption':'none','flow':'xtls-rprx-vision'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':sni,'fingerprint':'chrome','publicKey':public,'shortId':short,'spiderX':'/'}}}))

if __name__=='__main__':main()
