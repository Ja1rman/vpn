#!/usr/bin/env python3
"""Move deployment credentials between private files and environment variables.

The monitoring CA signing key and x-ui user database never enter CI.
"""
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = ('VPN_SSH_PASSWORDS_JSON', 'VPN_SSH_KNOWN_HOSTS',
                'VPN_OUTBOUNDS_JSON', 'VPN_MONITORING_PASSWORD',
                'VPN_MONITORING_TLS_JSON')


def inventory():
    inv = json.loads((ROOT / 'inventory/hosts.json').read_text())
    hosts = [inv['entry']] + inv['nodes']
    for host in hosts:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}', host['name']):
            raise ValueError('Invalid inventory host name')
    if len({h['name'] for h in hosts}) != len(hosts):
        raise ValueError('Duplicate inventory host name')
    return inv, hosts


def outbound_paths(inv):
    paths = {p for node in inv['nodes'] for p in node['outbounds']}
    for path in paths:
        if not re.fullmatch(r'\.local/outbounds/[a-zA-Z0-9_.-]+\.json', path):
            raise ValueError('CI requires outbound files directly under .local/outbounds/')
    return paths


def local_secrets():
    """Return secret strings in memory, without writing a plaintext bundle."""
    inv, hosts = inventory()
    passwords = {}
    for host in hosts:
        path = ROOT / '.local/ssh' / (host['name'] + '.password')
        if host['name'] == 'breeze-reef' and not path.exists():
            path = ROOT / '.local/ssh/nl.password'
        passwords[host['name']] = path.read_text().strip()
    outbounds = {path: json.loads((ROOT / path).read_text()) for path in outbound_paths(inv)}
    pki = ROOT / '.local/pki'
    tls = {'ca_cert': (pki / 'ca.crt').read_text(), 'nodes': {}}
    for name in ['client'] + [h['name'] for h in hosts]:
        pair = {'cert': (pki / name / 'cert.pem').read_text(),
                'key': (pki / name / 'key.pem').read_text()}
        if name == 'client':
            tls['client'] = pair
        else:
            tls['nodes'][name] = pair
    access = json.loads((ROOT / '.local/access.json').read_text())
    values = {'VPN_SSH_PASSWORDS_JSON': json.dumps(passwords),
              'VPN_SSH_KNOWN_HOSTS': (ROOT / '.local/ssh/known_hosts').read_text(),
              'VPN_OUTBOUNDS_JSON': json.dumps(outbounds),
              'VPN_MONITORING_PASSWORD': access['password'],
              'VPN_MONITORING_TLS_JSON': json.dumps(tls)}
    private_alertmanager = ROOT / '.local/alertmanager.yml'
    if private_alertmanager.exists():
        values['VPN_ALERTMANAGER_CONFIG'] = private_alertmanager.read_text()
    for name, value in values.items():
        if not value or len(value.encode()) >= 48 * 1024:
            raise ValueError(name + ' is empty or exceeds the GitHub secret size limit')
    return values, access['username']


def secret_json(name):
    try:
        return json.loads(os.environ[name])
    except (KeyError, ValueError):
        raise ValueError('Missing or invalid JSON in ' + name) from None


def mask_values(value):
    if isinstance(value, dict):
        for child in value.values():
            mask_values(child)
    elif isinstance(value, list):
        for child in value:
            mask_values(child)
    elif isinstance(value, str):
        for part in {value, *value.splitlines()}:
            if len(part) >= 4:
                escaped = part.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
                print('::add-mask::' + escaped, flush=True)


def write_private(path, value):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_text(value)
    path.chmod(0o600)


def hydrate():
    """Create only the private files named by the trusted inventory."""
    os.umask(0o077)
    for name in SECRET_NAMES:
        if not os.environ.get(name):
            raise ValueError('Required GitHub Secret is missing: ' + name)
    # Structured secrets must mask their nested values too, before subprocesses
    # can emit errors. No environment dumps, caches or credential artifacts.
    for name in SECRET_NAMES + ('VPN_ALERTMANAGER_CONFIG',):
        value = os.environ.get(name, '')
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            mask_values(value)
            if name.endswith('_JSON'):
                mask_values(secret_json(name))
    inv, hosts = inventory()
    passwords = secret_json('VPN_SSH_PASSWORDS_JSON')
    outbounds = secret_json('VPN_OUTBOUNDS_JSON')
    tls = secret_json('VPN_MONITORING_TLS_JSON')
    for host in hosts:
        name = host['name']
        if not passwords.get(name):
            raise ValueError('SSH credential missing for ' + name)
        write_private(ROOT / '.local/ssh' / (name + '.password'), passwords[name] + '\n')
    write_private(ROOT / '.local/ssh/known_hosts', os.environ['VPN_SSH_KNOWN_HOSTS'])
    for path in outbound_paths(inv):
        if path not in outbounds:
            raise ValueError('Outbound secret missing for ' + path)
        write_private(ROOT / path, json.dumps(outbounds[path]))
    access = {'username': os.environ.get('VPN_MONITORING_USERNAME') or 'admin',
              'password': os.environ['VPN_MONITORING_PASSWORD'],
              'base_url': 'http://' + inv['entry']['address']}
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', access['username']) or len(access['password']) < 24:
        raise ValueError('Invalid monitoring login or short monitoring password')
    write_private(ROOT / '.local/access.json', json.dumps(access))
    write_private(ROOT / '.local/grafana-admin-password', access['password'] + '\n')
    pki = ROOT / '.local/pki'
    write_private(pki / 'ca.crt', tls['ca_cert'])
    for name in ['client'] + [h['name'] for h in hosts]:
        pair = tls['client'] if name == 'client' else tls['nodes'][name]
        write_private(pki / name / 'cert.pem', pair['cert'])
        write_private(pki / name / 'key.pem', pair['key'])
        write_private(pki / name / 'ca.crt', tls['ca_cert'])
    # certificates.py only copies these existing leaf certificates; it has no
    # signing key and cannot issue a new certificate or replace the CA in CI.
    return inv, hosts
