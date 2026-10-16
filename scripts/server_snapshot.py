#!/usr/bin/env python3
"""Read-only service/container/disk snapshot; run as root on the server."""
import json
import os
from pathlib import Path
import subprocess

def output(*args):
    return subprocess.check_output(args).decode()

def snapshot():
    names=[line.split()[0] for line in output('systemctl','list-units','--type=service','--state=running','--no-legend','--plain').splitlines() if line.split()]
    services={}
    for name in names:
        properties=output('systemctl','show',name,'-p','MainPID','-p','ActiveState','-p','SubState','-p','ActiveEnterTimestampMonotonic')
        services[name]=dict(line.split('=',1) for line in properties.splitlines())
    ids=output('docker','ps','-q').split()
    containers=json.loads(output('docker','inspect',*ids)) if ids else []
    containers=[{'id':x['Id'],'name':x['Name'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'status':x['State']['Status'],'health':x['State'].get('Health',{}).get('Status')} for x in containers]
    xrays=[]
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            command=path.read_bytes().split(b'\0')[0]
            if command.endswith(b'xray-linux-amd64') or command==b'/opt/vpn-balancer/xray':
                xrays.append({'pid':int(path.parent.name),'executable':command.decode()})
        except (OSError,ValueError):pass
    disk=os.statvfs('/')
    return {'services':services,'containers':containers,'xrays':sorted(xrays,key=lambda x:x['pid']),'disk':{'total_bytes':disk.f_blocks*disk.f_frsize,'available_bytes':disk.f_bavail*disk.f_frsize,'free_bytes':disk.f_bfree*disk.f_frsize,'used_bytes':(disk.f_blocks-disk.f_bfree)*disk.f_frsize}}

if __name__=='__main__':print(json.dumps(snapshot(),indent=2))
