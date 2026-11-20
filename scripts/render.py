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
from priority_pool import build_priority_chain
from vpn_env import env, port, expand, load_json

ROOT = Path(__file__).resolve().parents[1]
ENCRYPTED_PROTOCOLS = {"vless", "hysteria", "trojan", "shadowsocks", "vmess"}

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def build_balancer(inventory):
    outbounds = []
    for node in inventory["nodes"]:
        overrides = node.get('outbound_tags', {})
        if not isinstance(overrides, dict) or set(overrides) - set(node['outbounds']):
            raise ValueError('outbound_tags must reference files of its own node')
        for index, filename in enumerate(node["outbounds"]):
            outbound = json.loads((ROOT / filename).read_text())
            if outbound.get("protocol") not in ENCRYPTED_PROTOCOLS:
                raise ValueError("Only encrypted remote proxies may enter the VPN pool")
            tag = overrides.get(filename, f"pool-{node['name']}-{index}")
            if not isinstance(tag, str) or not re.fullmatch(r'pool-[a-zA-Z0-9_-]+', tag):
                raise ValueError('Invalid stable pool outbound tag')
            outbound["tag"] = tag
            outbounds.append(outbound)
    if not outbounds:
        raise ValueError("At least one exit must be configured")
    settings = inventory["balancer"]
    if settings["strategy"] not in {"priority", "roundRobin", "leastPing"}:
        raise ValueError("strategy must be priority, roundRobin or leastPing")
    original_tags = [o['tag'] for o in outbounds]
    reserves = settings.get('reserve_outbounds', [])
    if not isinstance(reserves, list) or (reserves and settings['strategy'] != 'priority'):
        raise ValueError('reserve_outbounds must be a list and requires priority mode')
    reserve_tags = []
    private = (ROOT / '.local/outbounds').resolve()
    for reserve in reserves:
        if not isinstance(reserve, dict) or set(reserve) != {'name', 'file'}:
            raise ValueError('Each reserve outbound requires name and file')
        name, filename = reserve['name'], reserve['file']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}', name):
            raise ValueError('Invalid reserve outbound name')
        tag = 'pool-reserve-' + name
        if tag in reserve_tags or tag in original_tags:
            raise ValueError('Duplicate reserve outbound name or tag')
        if not isinstance(filename, str):
            raise ValueError('Reserve outbound file must be under .local/outbounds')
        path = Path(filename)
        if path.parts[:2] != ('.local', 'outbounds') or '..' in path.parts or path.suffix != '.json' \
                or not (ROOT / path).resolve().is_relative_to(private):
            raise ValueError('Reserve outbound file must be under .local/outbounds')
        outbound = json.loads((ROOT / path).read_text())
        if outbound.get('protocol') not in ENCRYPTED_PROTOCOLS:
            raise ValueError('Only encrypted remote proxies may enter the VPN pool')
        outbound['tag'] = tag
        outbounds.append(outbound)
        reserve_tags.append(tag)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "pool-socks", "listen": env('VPN_LOOPBACK_IP'), "port": settings["socks_port"], "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
            {"tag": "api", "listen": env('VPN_LOOPBACK_IP'), "port": settings["api_port"], "protocol": "tunnel", "settings": {"address": env('VPN_LOOPBACK_IP')}}
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
    if settings['strategy'] == 'priority':
        preferred = settings.get('priority_order', [])
        if not isinstance(preferred, list) or any(not isinstance(tag, str) for tag in preferred) or \
                len(set(preferred)) != len(preferred) or any(tag not in original_tags for tag in preferred):
            raise ValueError('priority_order must contain unique, existing original outbound tags')
        order = preferred + [tag for tag in original_tags if tag not in preferred] + reserve_tags
        bridges, rules, balancers = build_priority_chain(order)
        config['outbounds'].extend(bridges)
        config['routing']['rules'].extend(rules)
        config['routing']['balancers'] = balancers
    return config

def prometheus_config(inv):
    loopback = env('VPN_LOOPBACK_IP')
    monitoring = inv['monitoring']
    endpoints = {name: monitoring.get(name + '_port', port(variable)) for name, variable in [
        ('prometheus', 'VPN_PROMETHEUS_PORT'), ('alertmanager', 'VPN_ALERTMANAGER_PORT'),
        ('blackbox', 'VPN_BLACKBOX_PORT')]}
    local = lambda value: f'{loopback}:{value}'
    base = {"global": {"scrape_interval": "15s", "evaluation_interval": "15s", "external_labels": {"cluster": "vpn"}},
            "rule_files": ["/etc/vpn-monitoring/prometheus/alerts.yml"],
            "alerting": {"alertmanagers": [{"static_configs": [{"targets": [local(endpoints['alertmanager'])]}]}]}, "scrape_configs": []}
    jobs = base["scrape_configs"]
    for job, listen_port in endpoints.items():
        jobs.append({"job_name":job,"static_configs":[{"targets":[local(listen_port)]}]})
    jobs.append({"job_name":"node", "scheme":"https", "tls_config":{"ca_file":"/etc/vpn-monitoring/tls/ca.crt","cert_file":"/etc/vpn-monitoring/tls/client.crt","key_file":"/etc/vpn-monitoring/tls/client.key"}, "file_sd_configs":[{"files":["/etc/vpn-monitoring/prometheus/nodes.json"]}]})
    targets=[{"targets":[local(inv['monitoring']['node_port'])],"labels":{"host":inv['entry']['name']}}]
    targets += [{"targets":[f"{n['address']}:{inv['monitoring']['node_port']}"],"labels":{"host":n['name']}} for n in inv['nodes']]
    def probe_ports(host, default):
        ports=host.get('vpn_probe_ports',default)
        if not isinstance(ports,list) or not ports or any(type(p) is not int or not 1<=p<=65535 for p in ports):
            raise ValueError('vpn_probe_ports must be a nonempty list of TCP ports')
        return list(dict.fromkeys(ports))
    entry_ports=probe_ports(inv['entry'],[port('VPN_VLESS_NATIVE_PORT'),port('VPN_HTTP_LEGACY_PORT')])+[inv['balancer']['socks_port']]
    probes=[{"targets":[local(p) for p in dict.fromkeys(entry_ports)],"labels":{"host":"entry"}}]
    probes += [{"targets":[f"{n['address']}:{p}" for p in probe_ports(n,[n.get('vpn_port',port('VPN_EXIT_TLS_PORT'))])],"labels":{"host":n['name']}} for n in inv['nodes']]
    if 'failover' in inv:
        probes += [
            {"targets":[local(port('VPN_AUTO_REALITY_PORT')),local(port('VPN_AUTO_TLS_PUBLIC_PORT'))],"labels":{"host":"entry","service":"failover","role":"frontend"}},
            {"targets":[local(port('VPN_VLESS_AUTH_PORT'))],"labels":{"host":"entry","service":"failover","role":"auth"}},
            {"targets":[local(port('VPN_AUTO_SUBSCRIPTION_PORT'))],"labels":{"host":"entry","service":"failover","role":"subscription"}},
        ]
    jobs.append({"job_name":"vpn-tcp", "metrics_path":"/probe", "params":{"module":["tcp_connect"]}, "file_sd_configs":[{"files":["/etc/vpn-monitoring/prometheus/vpn-targets.json"]}], "relabel_configs":[{"source_labels":["__address__"],"target_label":"__param_target"},{"source_labels":["__param_target"],"target_label":"instance"},{"target_label":"__address__","replacement":local(endpoints['blackbox'])}]})
    urls=inv.get('failover',{}).get('probe_urls',[inv['balancer']['probe_url']])
    egresses=[{"targets":urls,"labels":{"host":"entry","service":"legacy","probe_module":"http_vpn"}}]
    if 'failover' in inv:
        egresses.append({"targets":urls,"labels":{"host":"entry","service":"failover","probe_module":"http_vpn_failover"}})
    jobs.append({"job_name":"vpn-egress", "metrics_path":"/probe", "static_configs":egresses,
                 "relabel_configs":[{"source_labels":["__address__"],"target_label":"__param_target"},
                                    {"source_labels":["__param_target"],"target_label":"instance"},
                                    {"source_labels":["probe_module"],"target_label":"__param_module"},
                                    {"action":"labeldrop","regex":"probe_module"},
                                    {"target_label":"__address__","replacement":local(endpoints['blackbox'])}]})
    return base, targets, probes

def render_monitoring_templates(directory):
    # Only VPN_* placeholders are expanded: Nginx/Grafana variables stay intact.
    for relative in ('compose.yml', 'blackbox.yml', 'nginx.conf', 'nginx-grafana-https.conf',
                     'grafana/provisioning/datasources/prometheus.yml'):
        path = directory / relative
        path.write_text(expand(path.read_text()))

def main():
    os.umask(0o077)
    inv=load_json(ROOT/'inventory/hosts.json')
    for n in [inv['entry']]+inv['nodes']:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',n['name']): raise ValueError('Invalid node name')
        if n['network_budget_mbps'] <= 0: raise ValueError('network_budget_mbps must be positive')
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]+',n['interface']): raise ValueError('Invalid network interface')
    if len({n['name'] for n in [inv['entry']]+inv['nodes']})!=len(inv['nodes'])+1:raise ValueError('Node names must be unique')
    out=ROOT/'.local/rendered'
    out.mkdir(parents=True,exist_ok=True)
    shutil.copytree(ROOT/'monitoring',out/'monitoring',dirs_exist_ok=True)
    render_monitoring_templates(out/'monitoring')
    private_alertmanager=ROOT/'.local/alertmanager.yml'
    if private_alertmanager.exists():
        alertmanager=out/'monitoring/alertmanager/alertmanager.yml'
        shutil.copyfile(private_alertmanager,alertmanager)
        alertmanager.chmod(0o600)
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
