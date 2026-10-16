#!/usr/bin/env python3
"""Render deployment files locally; secrets stay under .local/. Python >= 3.10."""
import copy
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def build_balancer(inventory):
    outbounds = []
    for node in inventory["nodes"]:
        for index, filename in enumerate(node["outbounds"]):
            outbound = json.loads((ROOT / filename).read_text())
            if outbound.get("protocol") not in {"vless", "hysteria", "trojan", "shadowsocks", "vmess"}:
                raise ValueError("Only encrypted remote proxies may enter the VPN pool")
            outbound["tag"] = f"pool-{node['name']}-{index}"
            outbounds.append(outbound)
    if not outbounds:
        raise ValueError("At least one exit must be configured")
    settings = inventory["balancer"]
    if settings["strategy"] not in {"roundRobin", "leastPing"}:
        raise ValueError("strategy must be roundRobin or leastPing")
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "pool-socks", "listen": "127.0.0.1", "port": settings["socks_port"], "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
            {"tag": "api", "listen": "127.0.0.1", "port": settings["api_port"], "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}
        ],
        "outbounds": [{"tag": "blocked", "protocol": "blackhole", "settings": {}}] + outbounds,
        "api": {"tag": "api", "services": ["HandlerService", "RoutingService", "StatsService"]},
        "stats": {},
        "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                {"type": "field", "inboundTag": ["pool-socks"], "balancerTag": "vpn-pool"}
            ],
            "balancers": [{"tag": "vpn-pool", "selector": [o['tag'] for o in outbounds], "fallbackTag": "blocked", "strategy": {"type": settings["strategy"]}}]
        },
        "observatory": {"subjectSelector": ["pool-"], "probeUrl": settings["probe_url"], "probeInterval": settings["probe_interval"], "enableConcurrency": True}
    }

def prometheus_config(inv):
    base = {"global": {"scrape_interval": "15s", "evaluation_interval": "15s", "external_labels": {"cluster": "vpn"}},
            "rule_files": ["/etc/vpn-monitoring/prometheus/alerts.yml"],
            "alerting": {"alertmanagers": [{"static_configs": [{"targets": ["127.0.0.1:9093"]}]}]}, "scrape_configs": []}
    jobs = base["scrape_configs"]
    for job, port in [("prometheus",9090),("alertmanager",9093),("blackbox",9115)]:
        jobs.append({"job_name":job,"static_configs":[{"targets":[f"127.0.0.1:{port}"]}]})
    jobs.append({"job_name":"node", "scheme":"https", "tls_config":{"ca_file":"/etc/vpn-monitoring/tls/ca.crt","cert_file":"/etc/vpn-monitoring/tls/client.crt","key_file":"/etc/vpn-monitoring/tls/client.key"}, "file_sd_configs":[{"files":["/etc/vpn-monitoring/prometheus/nodes.json"]}]})
    targets=[{"targets":[f"127.0.0.1:{inv['monitoring']['node_port']}"],"labels":{"host":inv['entry']['name']}}]
    targets += [{"targets":[f"{n['address']}:{inv['monitoring']['node_port']}"],"labels":{"host":n['name']}} for n in inv['nodes']]
    probes=[{"targets":["127.0.0.1:33172","127.0.0.1:58663", f"127.0.0.1:{inv['balancer']['socks_port']}"],"labels":{"host":"entry"}}]
    probes += [{"targets":[f"{n['address']}:{n.get('vpn_port',443)}"],"labels":{"host":n['name']}} for n in inv['nodes']]
    jobs.append({"job_name":"vpn-tcp", "metrics_path":"/probe", "params":{"module":["tcp_connect"]}, "file_sd_configs":[{"files":["/etc/vpn-monitoring/prometheus/vpn-targets.json"]}], "relabel_configs":[{"source_labels":["__address__"],"target_label":"__param_target"},{"source_labels":["__param_target"],"target_label":"instance"},{"target_label":"__address__","replacement":"127.0.0.1:9115"}]})
    jobs.append({"job_name":"vpn-egress", "metrics_path":"/probe", "params":{"module":["http_vpn"]}, "static_configs":[{"targets":[inv['balancer']['probe_url']],"labels":{"host":"entry"}}], "relabel_configs":[{"source_labels":["__address__"],"target_label":"__param_target"},{"source_labels":["__param_target"],"target_label":"instance"},{"target_label":"__address__","replacement":"127.0.0.1:9115"}]})
    return base, targets, probes

def main():
    os.umask(0o077)
    inv=json.loads((ROOT/'inventory/hosts.json').read_text())
    for n in [inv['entry']]+inv['nodes']:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',n['name']): raise ValueError('Invalid node name')
        if n['network_budget_mbps'] <= 0: raise ValueError('network_budget_mbps must be positive')
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]+',n['interface']): raise ValueError('Invalid network interface')
    if len({n['name'] for n in [inv['entry']]+inv['nodes']})!=len(inv['nodes'])+1:raise ValueError('Node names must be unique')
    out=ROOT/'.local/rendered'
    out.mkdir(parents=True,exist_ok=True)
    shutil.copytree(ROOT/'monitoring',out/'monitoring',dirs_exist_ok=True)
    private_alertmanager=ROOT/'.local/alertmanager.yml'
    if private_alertmanager.exists():
        alertmanager=out/'monitoring/alertmanager/alertmanager.yml'
        shutil.copyfile(private_alertmanager,alertmanager)
        alertmanager.chmod(0o600)
    compose=out/'monitoring/compose.yml'
    compose.write_text(compose.read_text().replace('212.22.70.156',inv['entry']['address']))
    write_json(out/'balancer/config.json', build_balancer(inv))
    prom, targets, probes = prometheus_config(inv)
    write_json(out/'monitoring/prometheus/prometheus.yml', prom)
    write_json(out/'monitoring/prometheus/nodes.json',targets)
    write_json(out/'monitoring/prometheus/vpn-targets.json',probes)
    for n in [inv['entry']]+inv['nodes']:
        d=out/'nodes'/n['name']; d.mkdir(parents=True,exist_ok=True)
        (d/'capacity.prom').write_text('# HELP vpn_network_capacity_bits Configured aggregate RX+TX network budget, bits/s.\n# TYPE vpn_network_capacity_bits gauge\n'+f'vpn_network_capacity_bits{{device="{n["interface"]}"}} {n["network_budget_mbps"]*1000000}\n')
    pwd=ROOT/'.local/grafana-admin-password'
    if not pwd.exists(): pwd.write_text(secrets.token_urlsafe(24)+'\n')
    shutil.copyfile(pwd,out/'monitoring/grafana/admin-password')
    access=ROOT/'.local/access.json'
    if not access.exists():
        write_json(access,{'username':'admin','password':pwd.read_text().strip(),'base_url':'http://'+inv['entry']['address']})
    credentials=json.loads(access.read_text())
    (out/'monitoring/grafana/admin-password').write_text(credentials['password']+'\n')
    (out/'monitoring/grafana/admin-user').write_text(credentials['username']+'\n')
    auth=subprocess.run(['htpasswd','-niB','-C','12',credentials['username']],input=(credentials['password']+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    (out/'monitoring/monitoring.htpasswd').write_bytes(auth.stdout)
    (ROOT/'.local/access.md').write_text('# Доступ к мониторингу VPN\n\n'+f"- Grafana: {credentials['base_url']}/grafana/\n- Alertmanager: {credentials['base_url']}/alerts/\n- Prometheus: {credentials['base_url']}/prometheus/\n- Логин: `{credentials['username']}`\n- Пароль: `{credentials['password']}`\n\nGrafana использует форму входа. Alertmanager и Prometheus — HTTP Basic Auth.\nЭтот файл и access.json исключены из Git. HTTP передаёт данные и реквизиты без шифрования.\n")
    print('Rendered .local/rendered (private; excluded from Git)')

if __name__ == '__main__': main()
