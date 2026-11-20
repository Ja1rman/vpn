"""Create isolated endpoint values for offline tests when explicitly enabled."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket

from vpn_env import configured_values, expand


ROOT = Path(__file__).resolve().parents[1]
_configured = False
_EXTRA_KEYS = ('VPN_TEST_SNIFF_PORT', 'VPN_TEST_EXIT_C_PORT', 'VPN_TEST_UNEXPECTED_PORT')


def _public_address(used):
    while True:
        candidate = ipaddress.IPv4Address(secrets.token_bytes(4))
        value = str(candidate)
        if candidate.is_global and not candidate.is_multicast and value not in used:
            used.add(value)
            return value


def _free_port(loopback, used):
    while True:
        with socket.socket() as listener:
            listener.bind((loopback, 0))
            value = listener.getsockname()[1]
        if value not in used:
            used.add(value)
            return str(value)


def _wildcard_address(family):
    """Ask the OS for a passive address without creating or binding a socket."""
    return socket.getaddrinfo(None, 0, family=family, type=socket.SOCK_STREAM,
                              flags=socket.AI_PASSIVE)[0][4][0]


def configure():
    """Set fresh endpoint fixtures once, without exposing deployment values."""
    global _configured
    if os.environ.get('VPN_TEST_MODE') != '1' or _configured:
        return
    names = set(configured_values()) | set(_EXTRA_KEYS)
    example = ROOT / '.env.example'
    if example.is_file():
        names.update(re.findall(r'(?m)^(VPN_[A-Z0-9_]+)=', example.read_text()))
    loopback = socket.gethostbyname('localhost')
    wildcard = _wildcard_address(socket.AF_INET)
    values = {
        'VPN_LOOPBACK_IP': loopback,
        'VPN_BIND_IP': wildcard,
        'VPN_BIND_IPV6_IP': _wildcard_address(socket.AF_INET6),
        'VPN_AUTO_SOURCE_IP': str(ipaddress.IPv4Address(loopback) + 1),
    }
    addresses, ports = set(values.values()), set()
    for name in sorted(names):
        if name.endswith('_PORT'):
            values[name] = _free_port(loopback, ports)
        elif name not in values and name.endswith(('_IP', '_ADDRESS')):
            values[name] = _public_address(addresses)
    values['VPN_AUTO_SOURCE_ADDRESS'] = values['VPN_AUTO_SOURCE_IP']
    if 'VPN_NODE_EXPORTER_PORT' in values:
        values['VPN_NODE_PORT'] = values['VPN_NODE_EXPORTER_PORT']
    for key, scheme, endpoint, path in (
        ('VPN_GRAFANA_URL', 'https', 'VPN_MONITORING_HTTPS_PORT', '/grafana/'),
        ('VPN_ALERTMANAGER_URL', 'http', 'VPN_MONITORING_HTTP_PORT', '/alerts/'),
        ('VPN_PROMETHEUS_URL', 'http', 'VPN_MONITORING_HTTP_PORT', '/prometheus/'),
    ):
        if endpoint in values and 'VPN_ENTRY_ADDRESS' in values:
            values[key] = f'{scheme}://{values["VPN_ENTRY_ADDRESS"]}:{values[endpoint]}{path}'
    os.environ.update(values)
    _configured = True


def render_alerts(destination):
    configure()
    if os.environ.get('VPN_TEST_MODE') != '1':
        raise ValueError('Alert fixtures require VPN_TEST_MODE=1')
    source = ROOT / 'tests/alerts.test.yml'
    text = expand(source.read_text())
    original = '../monitoring/prometheus/alerts.yml'
    if text.count(original) != 1:
        raise ValueError('Unexpected alert fixture rule path')
    rule = os.path.relpath(ROOT / 'monitoring/prometheus/alerts.yml', destination.parent)
    text = text.replace(original, rule)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alerts', type=Path, required=True, help='Private expanded promtool fixture path')
    args = parser.parse_args()
    render_alerts(args.alerts)
    print('Expanded alert fixture saved privately')


if __name__ == '__main__':
    main()
