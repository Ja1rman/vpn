"""Native Xray primary/backup chain, with one candidate at every stage."""


def build_priority_chain(tags):
    if not tags or len(set(tags)) != len(tags):
        raise ValueError('Priority pool requires nonempty, unique outbound tags')
    # Xray selectors match prefixes, not exact strings. Refuse ambiguous tags
    # rather than accidentally spreading traffic over multiple candidates.
    if any(sum(other.startswith(tag) for other in tags) != 1 for tag in tags):
        raise ValueError('Ambiguous outbound tag prefix in priority pool')
    bridges, rules, balancers = [], [], []
    for index, tag in enumerate(tags):
        name = 'vpn-pool' if index == 0 else 'vpn-pool-step-' + str(index)
        fallback = 'blocked'
        if index + 1 < len(tags):
            fallback = 'failover-hop-' + str(index + 1)
            bridges.append({'tag': fallback, 'protocol': 'loopback',
                            'settings': {'inboundTag': 'pool-fallback-' + str(index + 1)}})
        balancers.append({'tag': name, 'selector': [tag], 'fallbackTag': fallback,
                          'strategy': {'type': 'roundRobin'}})
        if index:
            rules.append({'type': 'field', 'inboundTag': ['pool-fallback-' + str(index)],
                          'balancerTag': name})
    return bridges, rules, balancers
