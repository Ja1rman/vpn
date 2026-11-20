#!/usr/bin/env python3
"""Import real subscription VLESS URIs into isolated native Xray clients."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import argparse
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from failover_subscription import LoopbackHTTPSConnection, MAX_BODY, Settings, SUB_PATH
from verify_auto_onboarding import account_rows, dns_probe
from verify_xray_vless import isolated_client, reflect_ipv4, require, XRAY


ADDRESS = Settings.address
TLS_PORTS = {env_port('VPN_VLESS_AUTH_PORT'): env_port('VPN_STANDARD_TLS_PORT'), env_port('VPN_PRIMARY_VLESS_PORT'): env_port('VPN_PRIMARY_TLS_PORT'), env_port('VPN_NL_RELAY_VLESS_PORT'): env_port('VPN_NL_RELAY_TLS_PORT'), env_port('VPN_THIRD_VLESS_PORT'): env_port('VPN_THIRD_TLS_PORT')}


def read_feed(port, sub_id, trust):
    path = '/sub/' + sub_id
    require(SUB_PATH.fullmatch(path), 'Unexpected x-ui subscription identifier format')
    with closing(LoopbackHTTPSConnection(ADDRESS, port, context=trust, timeout=6)) as client:
        client.request('GET', path, headers={'Accept': 'text/plain', 'Accept-Encoding': 'identity',
                                            'User-Agent': 'vpn-native-xray-canary/1.0'})
        response = client.getresponse()
        require(response.status == 200, 'An active VLESS subscription did not return HTTP 200')
        require(response.getheader('Content-Encoding', 'identity').lower() == 'identity',
                'The subscription response uses an unexpected content encoding')
        body = response.read(MAX_BODY + 1)
    require(0 < len(body) <= MAX_BODY, 'Invalid subscription response size')
    if b'://' not in body:
        compact = b''.join(body.split())
        body = base64.b64decode(compact + b'=' * (-len(compact) % 4), validate=True)
    return [line for line in body.decode('utf-8-sig').splitlines() if line.startswith('vless://')]


def import_profile(line, candidate=False):
    parsed = urlsplit(line)
    require(parsed.scheme == 'vless' and parsed.hostname == ADDRESS and parsed.port
            and parsed.password is None and not parsed.path, 'Unexpected VLESS endpoint in the local feed')
    uid = str(UUID(parsed.username))
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
    require(all(len(value) == 1 for value in query.values()), 'The VLESS URI repeats a query parameter')
    require(query.get('encryption', ['none']) == ['none'], 'Unsupported VLESS encryption')
    require(query.get('type', ['tcp'])[0] in ('tcp', 'raw'), 'Unsupported VLESS transport in the feed')
    require(query.get('headerType', ['none']) == ['none'], 'Unsupported VLESS TCP header')
    require(query.get('flow', [''])[0] in ('', 'xtls-rprx-vision'), 'Unsupported VLESS flow')
    require(query.get('packetEncoding', ['xudp'])[0] in ('xudp', ''), 'Unsupported VLESS UDP encoding')
    require(query.get('allowInsecure', ['false'])[0] in ('0', 'false', ''),
            'The subscription disables certificate verification')
    security = query.get('security', ['none'])[0]
    port = parsed.port
    if candidate and port in TLS_PORTS:
        require(security == 'none', 'A candidate source port already uses an unexpected TLS mode')
        port, security = TLS_PORTS[port], 'tls'
        query = dict(query, sni=[ADDRESS])
    stream = {'network': 'tcp', 'security': security}
    if security == 'tls':
        name = query.get('sni', [parsed.hostname])[0]
        require(name == ADDRESS, 'Unexpected TLS certificate name')
        stream['tlsSettings'] = {'serverName': name, 'allowInsecure': False}
        if query.get('alpn', [''])[0]:
            stream['tlsSettings']['alpn'] = query['alpn'][0].split(',')
        if query.get('fp', [''])[0]:
            stream['tlsSettings']['fingerprint'] = query['fp'][0]
    elif security == 'reality':
        key, short_id = query.get('pbk', [''])[0], query.get('sid', [''])[0]
        require(re.fullmatch(r'[A-Za-z0-9_-]{43}', key)
                and re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}', short_id), 'Invalid REALITY public parameters')
        require(query.get('sni', [''])[0] and query.get('fp', [''])[0], 'Missing REALITY SNI or fingerprint')
        stream['realitySettings'] = {'serverName': query['sni'][0], 'fingerprint': query['fp'][0],
                                    'publicKey': key, 'shortId': short_id,
                                    'spiderX': query.get('spx', ['/'])[0]}
    else:
        require(security == 'none', 'Unsupported VLESS security mode')
    return {'tag': 'subscription-profile', 'protocol': 'vless',
            'settings': {'address': parsed.hostname, 'port': port, 'id': uid,
                         'encryption': 'none', 'flow': query.get('flow', [''])[0]},
            'streamSettings': stream}


def validate_core(remote):
    with tempfile.TemporaryDirectory(prefix='vpn-uri-compile-') as directory:
        path = Path(directory) / 'client.json'
        path.write_text(json.dumps({'log': {'loglevel': 'none', 'access': 'none'}, 'outbounds': [remote]}))
        result = subprocess.run([str(XRAY), 'run', '-test', '-config', str(path)], capture_output=True,
                                timeout=8, env=dict(os.environ, XRAY_LOCATION_ASSET=str(XRAY.parent)))
    return result.returncode == 0


def verify(candidate):
    trust = ssl.create_default_context()
    accounts = list(dict.fromkeys(sub_id for sub_id, _uid in account_rows(Settings())))
    require(accounts, 'No active standard VLESS subscribers are available')
    counters, examples, failures = {}, {}, []
    for feed_port in (env_port('VPN_SUBSCRIPTION_PORT'), env_port('VPN_AUTO_SUBSCRIPTION_PORT')):
        count = 0
        for sub_id in accounts:
            links = read_feed(feed_port, sub_id, trust)
            require(links and (feed_port != env_port('VPN_AUTO_SUBSCRIPTION_PORT') or len(links) == 1), 'Unexpected VLESS profile count')
            for line in links:
                remote = import_profile(line, candidate)
                count += 1
                port = remote['settings']['port']
                if validate_core(remote):
                    examples.setdefault(port, remote)
                else:
                    failures.append({'feed_port': feed_port, 'vpn_port': port, 'native_config': 'failed'})
        counters[str(feed_port)] = {'subscriptions': len(accounts), 'vless_uris': count}
    checks = []
    for port, remote in sorted(examples.items()):
        row = {'port': port, 'native_config': 'passed', 'tcp_https': 'failed', 'udp_dns': 'failed'}
        try:
            with isolated_client(remote) as (local, account):
                try:
                    row['exit_ipv4'] = reflect_ipv4(local, account)
                    row['tcp_https'] = 'passed'
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                    pass
                try:
                    dns_probe(local, account)
                    row['udp_dns'] = 'passed'
                except (OSError, RuntimeError):
                    pass
        except (OSError, RuntimeError, subprocess.SubprocessError):
            row['client_start'] = 'failed'
        checks.append(row)
    return {'candidate_tls': candidate, 'feeds': counters, 'compile_failures': failures, 'checks': checks}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-tls', action='store_true',
                        help='Before publication, test the four TLS replacements derived from real plaintext URIs')
    args = parser.parse_args()
    try:
        result = verify(args.candidate_tls)
        print(json.dumps(result))
        if result['compile_failures'] or any(row['tcp_https'] != 'passed' or row['udp_dns'] != 'passed'
                                             for row in result['checks']):
            raise SystemExit(1)
    except (OSError, RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'verify-xray-subscriptions: ' + detail + '\n')


if __name__ == '__main__':
    main()
