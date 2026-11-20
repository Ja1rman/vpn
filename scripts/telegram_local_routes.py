"""Route authenticated VPN traffic for this host's Telegram proxies locally."""
import copy
import ipaddress

from vpn_env import env, port


MTPROTO_TAG = 'vpn-telegram-local-mtproto'
SOCKS_TAG = 'vpn-telegram-local-socks'
DD_TAG = 'vpn-telegram-local-dd'
MTPROTO_DD_TAG = DD_TAG
TAGS = (MTPROTO_TAG, SOCKS_TAG, DD_TAG)
VPN_PROTOCOLS = frozenset(('vless', 'shadowsocks', 'http', 'mixed', 'socks', 'wireguard'))
LEADING_RULES = [
    {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
    {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'blocked'},
    {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'blocked'},
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def normalized_routing(routing):
    return dict(routing, rules=[{key: value for key, value in rule.items() if key != 'enabled'}
                                for rule in routing['rules'] if rule.get('enabled', True)])


def _nonempty(value):
    return isinstance(value, str) and bool(value)


def _accounts(accounts):
    if not isinstance(accounts, list) or not accounts:
        return False
    return all(isinstance(account, dict) and any(
        _nonempty(account.get(user)) and _nonempty(account.get(password))
        for user, password in (('user', 'pass'), ('username', 'password')))
        for account in accounts)


def _authenticated(inbound):
    settings = inbound.get('settings', {})
    if not isinstance(settings, dict):
        return False
    protocol = inbound['protocol']
    if protocol == 'vless':
        clients = settings.get('clients')
        return (settings.get('decryption') == 'none' and isinstance(clients, list) and bool(clients)
                and all(isinstance(client, dict) and _nonempty(client.get('id')) for client in clients))
    if protocol == 'shadowsocks':
        clients = settings.get('clients')
        return (_nonempty(settings.get('method')) and settings['method'] != 'none'
                and ((_nonempty(settings.get('password')) and not clients)
                     or (isinstance(clients, list) and bool(clients)
                         and all(isinstance(client, dict) and _nonempty(client.get('password'))
                                 for client in clients))))
    if protocol == 'wireguard':
        peers = settings.get('peers')
        return (_nonempty(settings.get('secretKey')) and isinstance(peers, list) and bool(peers)
                and all(isinstance(peer, dict) and _nonempty(peer.get('publicKey')) for peer in peers))
    return _accounts(settings.get('accounts')) and (
        protocol == 'http' or settings.get('auth') == 'password')


def eligible_inbound_tags(config):
    """Validate authoritative runtime identities and explicit VPN authentication."""
    inbounds = config.get('inbounds')
    require(isinstance(inbounds, list) and bool(inbounds), 'Main runtime has no inbound identities')
    seen, selected = set(), []
    for inbound in inbounds:
        require(isinstance(inbound, dict), 'Unexpected main inbound identity')
        tag = inbound.get('tag')
        require(_nonempty(tag) and tag not in seen and tag not in TAGS,
                'Missing, duplicate or conflicting main inbound tag')
        seen.add(tag)
        if tag == 'api' or inbound.get('protocol') not in VPN_PROTOCOLS:
            continue
        listen_port = inbound.get('port')
        require(isinstance(listen_port, int) and not isinstance(listen_port, bool)
                and 0 < listen_port < 65536, 'Invalid authenticated VPN inbound port')
        require(_authenticated(inbound), 'A selected VPN inbound lacks explicit authentication')
        selected.append(tag)
    require(selected, 'No authenticated VPN inputs are available for local Telegram routes')
    return selected


def _endpoints():
    public = ipaddress.IPv4Address(env('VPN_ENTRY_ADDRESS'))
    loopback = ipaddress.IPv4Address(env('VPN_LOOPBACK_IP'))
    require(public.is_global and not public.is_multicast, 'Expected a public entry IPv4 address')
    require(loopback.is_loopback, 'Telegram backends must use IPv4 loopback')
    mtproto_public, socks_public = port('VPN_MTPROTO_PUBLIC_PORT'), port('VPN_TELEGRAM_SOCKS_PORT')
    mtproto_backend, dd_port = port('VPN_MTPROTO_PORT'), port('VPN_MTPROTO_DD_PORT')
    require(len({mtproto_public, socks_public, dd_port}) == 3
            and len({mtproto_backend, socks_public, dd_port}) == 3,
            'Telegram proxy roles have conflicting ports')
    return str(public), str(loopback), ((MTPROTO_TAG, mtproto_public, mtproto_backend),
                                       (SOCKS_TAG, socks_public, socks_public),
                                       (DD_TAG, dd_port, dd_port))


def expected_rules(inbound_tags):
    require(isinstance(inbound_tags, (list, tuple)) and bool(inbound_tags)
            and all(_nonempty(tag) and tag != 'api' and tag not in TAGS for tag in inbound_tags)
            and len(inbound_tags) == len(set(inbound_tags)), 'Invalid authenticated VPN input tag set')
    public, _loopback, endpoints = _endpoints()
    return [{'type': 'field', 'ruleTag': tag, 'inboundTag': list(inbound_tags),
             'network': 'tcp', 'ip': [public + '/32'], 'port': str(public_port), 'outboundTag': tag}
            for tag, public_port, _backend in endpoints]


def expected_outbounds():
    _public, loopback, endpoints = _endpoints()
    return [{'tag': tag, 'protocol': 'freedom', 'settings': {
                'redirect': f'{loopback}:{backend}',
                'finalRules': [{'action': 'allow', 'network': 'tcp',
                                'ip': [loopback + '/32'], 'port': str(backend)},
                               {'action': 'block'}]}}
            for tag, _public_port, backend in endpoints]


def transform(config, *, inbound_tags=None):
    """Clone a runtime or template; supplied tags must come from validated runtime."""
    tags = eligible_inbound_tags(config) if inbound_tags is None else inbound_tags
    additions, handlers = expected_rules(tags), expected_outbounds()
    routing = config.get('routing', {})
    rules, outbounds = routing.get('rules'), config.get('outbounds')
    require(isinstance(rules, list) and isinstance(outbounds, list)
            and not routing.get('script') and not routing.get('balancers'), 'Unexpected main routing topology')
    require(all(isinstance(rule, dict) and isinstance(rule.get('enabled', True), bool)
                and not rule.get('webhook') for rule in rules), 'Unexpected main rule state or side effects')
    require(len(rules) >= len(LEADING_RULES)
            and all(rule.get('enabled', True) for rule in rules[:len(LEADING_RULES)])
            and normalized_routing({'rules': rules[:len(LEADING_RULES)]})['rules'] == LEADING_RULES,
            'Main API, private-address or bittorrent blocks have changed')
    existing_tags = [outbound.get('tag') for outbound in outbounds if isinstance(outbound, dict)]
    require(len(existing_tags) == len(outbounds) and all(_nonempty(tag) for tag in existing_tags)
            and len(existing_tags) == len(set(existing_tags)), 'Missing or duplicate main outbound identities')
    require(not any(inbound.get('tag') in TAGS for inbound in config.get('inbounds', [])),
            'A local Telegram outbound tag conflicts with an inbound')
    references = [index for index, rule in enumerate(rules)
                  if rule.get('ruleTag') in TAGS or rule.get('outboundTag') in TAGS]
    existing = [outbound for outbound in outbounds if outbound['tag'] in TAGS]
    if references or existing:
        count = len(existing)
        require(count in (2, 3)
                and references == list(range(len(LEADING_RULES), len(LEADING_RULES) + count))
                and normalized_routing({'rules': [rules[index] for index in references]})['rules'] == additions[:count]
                and all(rules[index].get('enabled', True) for index in references)
                and existing == handlers[:count],
                'Conflicting or partial local Telegram routes; no configuration changed')
        result = copy.deepcopy(config)
        if count == 2:
            # Only the exact old pair is upgradeable; retain its raw rules and handlers.
            result['routing']['rules'].insert(len(LEADING_RULES) + count, additions[count])
            result['outbounds'].append(handlers[count])
        return result
    result = copy.deepcopy(config)
    result['routing']['rules'][len(LEADING_RULES):len(LEADING_RULES)] = additions
    result['outbounds'].extend(handlers)
    return result


def candidates(runtime, template):
    """Use live runtime auth tags even when the x-ui template only contains API."""
    require(normalized_routing(runtime['routing']) == normalized_routing(template['routing']),
            'Main runtime and template routing differ')
    require(runtime['outbounds'] == template['outbounds'], 'Main runtime and template outbounds differ')
    tags = eligible_inbound_tags(runtime)
    new_runtime = transform(runtime, inbound_tags=tags)
    new_template = transform(template, inbound_tags=tags)
    require(normalized_routing(new_runtime['routing']) == normalized_routing(new_template['routing'])
            and new_runtime['outbounds'] == new_template['outbounds'], 'Local Telegram candidate state differs')
    return new_runtime, new_template
