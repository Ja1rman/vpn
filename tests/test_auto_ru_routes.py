import copy
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from auto_ru_routes import DIRECT_TAG, HOP_TAG, INSPECT_RULE_TAG, RU_DOMAIN, RU_RULE_TAG, SNIFF_TAG, add_direct_ru
from failover_variant import build_pool
from update_failover_pool import append_plan, config_sites


class AutoRuRoutesTests(unittest.TestCase):
    def pool(self, count=2, *, direct=False):
        pairs = [('first', '1.1.1.1'), ('second', '8.8.8.8'), ('third', '9.9.9.9')][:count]
        settings = {
            'egresses': [{'name': name, 'address': address, 'source': 'main', 'tag': name}
                         for name, address in pairs],
            'probe_urls': ['https://example.com/generate_204'],
        }
        if direct:
            settings['direct_ru_ipv4'] = '8.8.4.4'
        main = {'outbounds': [
            {'tag': name, 'protocol': 'vless', 'settings': {'address': address, 'port': 443},
             'streamSettings': {'security': 'tls'}} for name, address in pairs
        ]}
        legacy = {'inbounds': [{'tag': 'pool-socks'}, {'tag': 'api'}], 'outbounds': [],
                  'policy': {'system': {}}, 'stats': {}}
        return build_pool(settings, main, legacy)[0]

    def test_optional_split_keeps_existing_priority_chain_and_loopback_listeners(self):
        base = self.pool()
        snapshot = copy.deepcopy(base)
        result = add_direct_ru(base, '8.8.4.4')
        self.assertEqual(result, self.pool(direct=True))
        self.assertEqual(base, snapshot)
        self.assertEqual(result['outbounds'][:len(base['outbounds'])], base['outbounds'])
        self.assertEqual(result['inbounds'][:-1], base['inbounds'])
        self.assertEqual((result['inbounds'][-1]['listen'], result['inbounds'][-1]['port']), ('127.0.0.1', 11094))
        self.assertTrue(result['inbounds'][-1]['sniffing']['routeOnly'])
        self.assertEqual(result['routing']['balancers'], base['routing']['balancers'])
        self.assertEqual(result['observatory'], base['observatory'])
        rules = result['routing']['rules']
        self.assertEqual(rules[:2], base['routing']['rules'][:2])
        self.assertEqual([r['ruleTag'] for r in rules[2:4]], [RU_RULE_TAG, INSPECT_RULE_TAG])
        self.assertEqual([r['network'] for r in rules[2:4]], ['tcp', 'tcp'])
        self.assertFalse(result['inbounds'][-1]['settings']['udp'])
        self.assertEqual(rules[2]['inboundTag'], ['pool-socks', SNIFF_TAG])
        self.assertEqual((rules[3]['inboundTag'], rules[3]['ip'], rules[3]['port']),
                         (['pool-socks'], ['0.0.0.0/0'], '80,443'))
        self.assertEqual(rules[4]['balancerTag'], 'vpn-pool')
        self.assertEqual(rules[4]['inboundTag'], ['pool-socks', SNIFF_TAG])
        self.assertEqual(rules[5:], base['routing']['rules'][3:])
        direct = next(o for o in result['outbounds'] if o['tag'] == DIRECT_TAG)
        self.assertNotIn('sendThrough', direct)
        self.assertEqual(direct['settings']['finalRules'][0]['ip'], ['geoip:private', '8.8.4.4/32'])

    def test_regexp_matches_only_the_requested_suffixes(self):
        domain = re.compile(RU_DOMAIN.removeprefix('regexp:'))
        for value in ('ya.ru', 'WWW.YA.RU.', 'пример.рф', 'почта.РУ', 'example.xn--p1ai', 'example.xn--p1ag.'):
            self.assertIsNotNone(domain.search(value), value)
        for value in ('bru', 'ru', 'ya.ru.org', 'пример.рус', 'пример.xn--p1acf', 'ya.ru..', 'ya.ru-example'):
            self.assertIsNone(domain.search(value), value)

    def test_append_preserves_exact_direct_topology_but_does_not_install_it(self):
        current, desired = self.pool(direct=True), self.pool(3, direct=True)
        sites, additions = append_plan(current, desired)
        self.assertEqual([o['tag'] for o in sites], ['pool-site-third'])
        self.assertEqual([o['tag'] for o in additions], ['pool-site-third', 'failover-hop-2'])
        with self.assertRaises(RuntimeError):
            append_plan(self.pool(), current)

        exposed = copy.deepcopy(current)
        exposed['inbounds'][-1]['listen'] = '0.0.0.0'
        wrong_hop = copy.deepcopy(current)
        next(o for o in wrong_hop['outbounds'] if o['tag'] == HOP_TAG)['settings']['port'] += 1
        missing_self_block = copy.deepcopy(current)
        next(o for o in missing_self_block['outbounds'] if o['tag'] == DIRECT_TAG)['settings']['finalRules'][0]['ip'].pop()
        for config in (exposed, wrong_hop, missing_self_block):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected VPN Auto'):
                config_sites(config)


if __name__ == '__main__':
    unittest.main()
