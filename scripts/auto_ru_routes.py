"""Build the optional domain split for the isolated VPN Auto pool."""
import copy
import ipaddress


POOL_TAG = 'pool-socks'
SNIFF_TAG = 'pool-ip-sniff'
SNIFF_PORT = 11094
HOP_TAG = 'vpn-auto-sniff-hop'
DIRECT_TAG = 'vpn-auto-ru-direct'
RU_RULE_TAG = 'vpn-auto-domain-ru'
INSPECT_RULE_TAG = 'vpn-auto-inspect-ip'
RU_DOMAIN = r'regexp:(?i)\.(ru|xn--p1ai|xn--p1ag|рф|ру)\.?$'
BASE_RULES = [
    {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
    {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'blocked'},
    {'type': 'field', 'inboundTag': [POOL_TAG], 'balancerTag': 'vpn-pool'},
]


def public_ipv4(address):
    if not isinstance(address, str):
        raise ValueError('VPN Auto direct address must be a public IPv4 string')
    ip = ipaddress.IPv4Address(address)
    if not ip.is_global or ip.is_multicast:
        raise ValueError('VPN Auto direct address must be a public IPv4 address')
    return str(ip)


def add_direct_ru(config, address):
    """Return a copy with a direct RU route and a loopback-only sniff hop.

    The address is the public egress and self-block value. It may be NATed,
    so the outbound uses the kernel's normal IPv4 source instead of binding it.
    """
    address = public_ipv4(address)
    if config['routing'].get('domainStrategy') != 'AsIs' or config['routing']['rules'][:3] != BASE_RULES:
        raise ValueError('Expected unchanged VPN Auto base routing')
    if any(i.get('tag') == SNIFF_TAG or str(i.get('port')) == str(SNIFF_PORT) for i in config['inbounds']):
        raise ValueError('VPN Auto sniff listener tag or port is already used')
    if any(o.get('tag') in (HOP_TAG, DIRECT_TAG) for o in config['outbounds']):
        raise ValueError('VPN Auto RU outbound tags are already used')
    if any(r.get('ruleTag') in (RU_RULE_TAG, INSPECT_RULE_TAG) for r in config['routing']['rules']):
        raise ValueError('VPN Auto RU route tags are already used')
    result = copy.deepcopy(config)
    result['inbounds'].append({
        'tag': SNIFF_TAG, 'listen': '127.0.0.1', 'port': SNIFF_PORT, 'protocol': 'socks',
        'settings': {'auth': 'noauth', 'udp': False},
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls'], 'routeOnly': True},
    })
    result['outbounds'].extend([
        {'tag': HOP_TAG, 'protocol': 'socks', 'settings': {'address': '127.0.0.1', 'port': SNIFF_PORT}},
        {'tag': DIRECT_TAG, 'protocol': 'freedom',
         'settings': {'finalRules': [{'action': 'block', 'ip': ['geoip:private', address + '/32']}]},
         'streamSettings': {'sockopt': {'domainStrategy': 'ForceIPv4'}}},
    ])
    result['routing']['rules'][2:3] = [
        {'type': 'field', 'ruleTag': RU_RULE_TAG, 'inboundTag': [POOL_TAG, SNIFF_TAG],
         'network': 'tcp', 'domain': [RU_DOMAIN], 'outboundTag': DIRECT_TAG},
        # An IP-only web request gets one inspection pass. IPv6 literals
        # stay in the old pool: the direct outbound deliberately uses IPv4.
        {'type': 'field', 'ruleTag': INSPECT_RULE_TAG, 'inboundTag': [POOL_TAG],
         'network': 'tcp', 'ip': ['0.0.0.0/0'], 'port': '80,443', 'outboundTag': HOP_TAG},
        {'type': 'field', 'inboundTag': [POOL_TAG, SNIFF_TAG], 'balancerTag': 'vpn-pool'},
    ]
    return result
