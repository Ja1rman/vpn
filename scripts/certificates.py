#!/usr/bin/env python3
"""Create private monitoring CA and mTLS certificates; CA never leaves laptop."""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def run(*args):
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)

def issue(ca, folder, name, san, client=False):
    folder.mkdir(parents=True,exist_ok=True)
    conf=folder/'openssl.cnf'
    conf.write_text('[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN='+name+'\n[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+('clientAuth' if client else 'serverAuth')+'\nsubjectAltName='+san+'\n')
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(folder/'key.pem'),'-out',str(folder/'request.csr'),'-config',str(conf))
    run('openssl','x509','-req','-in',str(folder/'request.csr'),'-CA',str(ca/'ca.crt'),'-CAkey',str(ca/'ca.key'),'-CAcreateserial','-days','397','-sha256','-extfile',str(conf),'-extensions','ext','-out',str(folder/'cert.pem'))
    shutil.copyfile(ca/'ca.crt',folder/'ca.crt')

def main():
    os.umask(0o077)
    inv=json.loads((ROOT/'inventory/hosts.json').read_text())
    ca=ROOT/'.local/pki';ca.mkdir(exist_ok=True)
    if not (ca/'ca.crt').exists():
        run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','3650','-subj','/CN=VPN monitoring CA','-keyout',str(ca/'ca.key'),'-out',str(ca/'ca.crt'))
    client=ca/'client'
    if not (client/'cert.pem').exists(): issue(ca,client,'prometheus','DNS:prometheus',True)
    dest=ROOT/'.local/rendered/monitoring/tls';dest.mkdir(exist_ok=True)
    for src,dst in [('cert.pem','client.crt'),('key.pem','client.key'),('ca.crt','ca.crt')]:shutil.copyfile(client/src,dest/dst)
    for node in [inv['entry']]+inv['nodes']:
        folder=ca/node['name']
        if not (folder/'cert.pem').exists():issue(ca,folder,node['name'],f'DNS:{node["name"]},IP:{node["address"]},IP:127.0.0.1')
        dest=ROOT/'.local/rendered/nodes'/node['name']
        for filename in ['cert.pem','key.pem','ca.crt']:shutil.copyfile(folder/filename,dest/filename)
        (dest/'web.yml').write_text('tls_server_config:\n  cert_file: /etc/vpn-node/cert.pem\n  key_file: /etc/vpn-node/key.pem\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: /etc/vpn-node/ca.crt\n  min_version: TLS12\n')
    print('mTLS certificates ready; signing key remains in .local/pki/ca.key')

if __name__=='__main__':main()
