#!/usr/bin/env python3
"""Failure drill in isolated processes on loopback; never stops production VPN."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

XRAY='/opt/vpn-balancer/xray'
ENV=dict(os.environ,XRAY_LOCATION_ASSET='/opt/vpn-balancer')

def main():
    os.umask(0o077)
    processes=[]
    with tempfile.TemporaryDirectory(prefix='vpn-failover-') as tmp:
        folder=Path(tmp)
        def start(name,config):
            path=folder/(name+'.json');path.write_text(json.dumps(config))
            log=(folder/(name+'.log')).open('wb')
            proc=subprocess.Popen([XRAY,'run','-config',str(path)],env=ENV,stdout=log,stderr=log)
            processes.append(proc);return proc
        def picks():
            result=subprocess.run([XRAY,'api','bi','--server=127.0.0.1:28101','fixture'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
            return result.stdout.decode().split('Selects:')[-1]
        def wait_for(predicate):
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                try:
                    value=picks()
                    if predicate(value):return value
                except subprocess.CalledProcessError:pass
                time.sleep(1)
            raise RuntimeError('Failover state did not converge: '+picks())
        uid=str(uuid.uuid4())
        for name,port in [('a',28102),('b',28103)]:
            start(name,{'log':{'loglevel':'error'},'inbounds':[{'tag':name,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[{'id':uid}],'decryption':'none'}}],'outbounds':[{'tag':'direct','protocol':'freedom'}]})
        exits=processes.copy()
        start('pool',{'log':{'loglevel':'error'},'api':{'tag':'api','services':['RoutingService']},'inbounds':[{'tag':'socks','listen':'127.0.0.1','port':28100,'protocol':'socks','settings':{'auth':'noauth'}},{'tag':'api','listen':'127.0.0.1','port':28101,'protocol':'tunnel','settings':{'address':'127.0.0.1'}}], 'outbounds':[{'tag':'blocked','protocol':'blackhole'}]+[{'tag':'fixture-'+name,'protocol':'vless','settings':{'address':'127.0.0.1','port':port,'id':uid,'encryption':'none'}} for name,port in [('a',28102),('b',28103)]], 'routing':{'rules':[{'type':'field','inboundTag':['api'],'outboundTag':'api'},{'type':'field','inboundTag':['socks'],'balancerTag':'fixture'}],'balancers':[{'tag':'fixture','selector':['fixture-'],'fallbackTag':'blocked','strategy':{'type':'roundRobin'}}]}, 'observatory':{'subjectSelector':['fixture-'],'probeUrl':'https://www.google.com/generate_204','probeInterval':'2s','enableConcurrency':True}})
        def request():return subprocess.run(['curl','--fail','--silent','--show-error','--max-time','8','--proxy','socks5h://127.0.0.1:28100','https://www.google.com/generate_204'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            wait_for(lambda x:'fixture-a' in x and 'fixture-b' in x)
            if request().returncode:raise RuntimeError('Initial pool check failed')
            exits[0].terminate();exits[0].wait(timeout=5)
            # bi lists candidates for roundRobin, including unhealthy members.
            # Verify actual requests: a non-filtering balancer would fail every other one.
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                if all(request().returncode==0 for _ in range(6)):break
                time.sleep(2)
            else:raise RuntimeError('Traffic failed after one fixture exit stopped')
            exits[1].terminate();exits[1].wait(timeout=5)
            time.sleep(5)
            if request().returncode==0:raise RuntimeError('Unexpected direct fallback when all exits failed')
            print(json.dumps({'isolated_two_exit_test':'passed','one_exit_failed':'traffic_continues','all_exits_failed':'blocked_without_direct_leak','production_services_untouched':True}))
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:proc.terminate()
            for proc in processes:proc.wait(timeout=10)

if __name__=='__main__':main()
