#!/usr/bin/env python3
"""End-to-end VLESS -> main Xray -> pool -> exit checks, without changing VPN."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

XRAY='/opt/vpn-balancer/xray'

def udp_dns(port):
    control=socket.create_connection(('127.0.0.1',port),timeout=10)
    control.sendall(b'\x05\x01\x00')
    if control.recv(2)!=b'\x05\x00':raise RuntimeError('SOCKS greeting failed')
    control.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('127.0.0.1')+b'\x00\x00')
    response=control.recv(262)
    if len(response)<10 or response[1]!=0 or response[3]!=1:raise RuntimeError('UDP associate failed')
    relay=(socket.inet_ntoa(response[4:8]),struct.unpack('!H',response[8:10])[0])
    if relay[0]=='0.0.0.0':relay=('127.0.0.1',relay[1])
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(15)
    query=b'\x51\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
    sock.sendto(b'\x00\x00\x00\x01'+socket.inet_aton('1.1.1.1')+struct.pack('!H',53)+query,relay)
    response,_=sock.recvfrom(4096)
    sock.close();control.close()
    if b'\x51\x37' not in response or len(response)<30:raise RuntimeError('No DNS response through VPN UDP')

def main():
    os.umask(0o077)
    config=json.loads(Path('/usr/local/x-ui/bin/config.json').read_text())
    inbound=next(i for i in config['inbounds'] if i['tag']=='in-46738-tcp')
    canary={'log':{'loglevel':'warning'},'inbounds':[{'tag':'test','listen':'127.0.0.1','port':28080,'protocol':'socks','settings':{'auth':'noauth','udp':True}}], 'outbounds':[{'tag':'main-vless','protocol':'vless','settings':{'address':'127.0.0.1','port':inbound['port'],'id':inbound['settings']['clients'][0]['id'],'encryption':'none'},'streamSettings':{'network':'tcp','security':'none'}}]}
    with tempfile.TemporaryDirectory(prefix='vpn-verify-') as tmp:
        path=Path(tmp)/'client.json';path.write_text(json.dumps(canary))
        log=(Path(tmp)/'xray.log').open('wb')
        process=subprocess.Popen([XRAY,'run','-config',str(path)],stdout=log,stderr=log,env=dict(os.environ,XRAY_LOCATION_ASSET='/opt/vpn-balancer'))
        try:
            time.sleep(1)
            ips=[]
            for _ in range(4):
                result=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','20','--proxy','socks5h://127.0.0.1:28080','https://api.ipify.org'],stdout=subprocess.PIPE,check=True)
                ips.append(result.stdout.decode().strip())
            udp_dns(28080)
            print(json.dumps({'vless_tcp_exit_ips':ips,'vless_udp_dns':'passed'}))
        finally:
            process.terminate();process.wait(timeout=10)

if __name__=='__main__':main()
