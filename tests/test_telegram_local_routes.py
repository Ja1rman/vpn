import copy
from pathlib import Path
import secrets
import sys
import unittest
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import telegram_local_routes as routes
import enable_failover_variant as variant


class TelegramLocalRoutesTests(unittest.TestCase):
    def runtime(self):
        password = secrets.token_urlsafe(24)
        inbounds = [
            {'tag': 'api', 'protocol': 'tunnel', 'port': port('VPN_XUI_API_PORT')},
            {'tag': 'vless-entry', 'protocol': 'vless', 'port': port('VPN_VLESS_AUTH_PORT'),
             'settings': {'decryption': 'none', 'clients': [{'id': str(uuid4())}]},
             'sniffing': {'enabled': False}},
            {'tag': 'ss-entry', 'protocol': 'shadowsocks', 'port': port('VPN_SS_PORT'),
             'settings': {'method': '2022-blake3-aes-256-gcm', 'password': password,
                          'clients': [{'password': secrets.token_urlsafe(24)}]}},
            {'tag': 'http-entry', 'protocol': 'http', 'port': port('VPN_HTTP_PRIMARY_PORT'),
             'settings': {'accounts': [{'user': 'fixture-user', 'pass': password}]}},
            {'tag': 'mixed-entry', 'protocol': 'mixed', 'port': port('VPN_HTTP_SOCKS_PORT'),
             'settings': {'auth': 'password', 'accounts': [{'username': 'fixture-user', 'password': password}]}},
            {'tag': 'socks-entry', 'protocol': 'socks', 'port': port('VPN_TEST_CANARY_PORT'),
             'settings': {'auth': 'password', 'accounts': [{'user': 'fixture-user', 'pass': password}]}},
            {'tag': 'wg-entry', 'protocol': 'wireguard', 'port': port('VPN_WIREGUARD_PRIMARY_PORT'),
             'settings': {'secretKey': secrets.token_urlsafe(32), 'peers': [{'publicKey': secrets.token_urlsafe(32)}]}},
            {'tag': 'unrelated-tunnel', 'protocol': 'tunnel', 'port': port('VPN_TEST_UNEXPECTED_PORT')},
        ]
        return {'log': {'loglevel': 'none'}, 'inbounds': inbounds,
                'outbounds': [{'tag': 'api', 'protocol': 'freedom'},
                              {'tag': 'blocked', 'protocol': 'blackhole'},
                              {'tag': 'vpn-egress-pool', 'protocol': 'socks',
                               'settings': {'address': env('VPN_LOOPBACK_IP'), 'port': port('VPN_BALANCER_SOCKS_PORT')}}],
                'routing': {'domainStrategy': 'AsIs', 'rules': copy.deepcopy(routes.LEADING_RULES) + [
                    {'type': 'field', 'inboundTag': ['vless-entry'], 'outboundTag': 'vpn-egress-pool'}]},
                'policy': {'system': {'statsOutboundUplink': True}}, 'stats': {}}

    def test_only_three_local_tcp_destinations_are_added_after_global_blocks(self):
        original = self.runtime()
        saved = copy.deepcopy(original)
        result = routes.transform(original)
        self.assertEqual(original, saved)
        self.assertEqual(result['inbounds'], saved['inbounds'])
        self.assertEqual(result['routing']['rules'][:3], saved['routing']['rules'][:3])
        self.assertEqual(result['routing']['rules'][6:], saved['routing']['rules'][3:])
        self.assertEqual(result['outbounds'][:-3], saved['outbounds'])
        self.assertEqual(result['policy'], saved['policy'])
        self.assertEqual(result['routing']['domainStrategy'], saved['routing']['domainStrategy'])
        selected = ['vless-entry', 'ss-entry', 'http-entry', 'mixed-entry', 'socks-entry', 'wg-entry']
        self.assertEqual(routes.eligible_inbound_tags(original), selected)
        self.assertEqual(result['routing']['rules'][3:6], routes.expected_rules(selected))
        self.assertEqual(result['outbounds'][-3:], routes.expected_outbounds())
        for rule in result['routing']['rules'][3:6]:
            self.assertEqual(rule['network'], 'tcp')
            self.assertEqual(rule['ip'], [env('VPN_ENTRY_ADDRESS') + '/32'])
            self.assertNotIn('api', rule['inboundTag'])
            self.assertNotIn('unrelated-tunnel', rule['inboundTag'])
        self.assertEqual(result['outbounds'][-3]['settings']['redirect'],
                         env('VPN_LOOPBACK_IP') + ':' + str(port('VPN_MTPROTO_PORT')))
        self.assertEqual(result['outbounds'][-2]['settings']['redirect'],
                         env('VPN_LOOPBACK_IP') + ':' + str(port('VPN_TELEGRAM_SOCKS_PORT')))
        self.assertEqual(result['outbounds'][-1]['settings']['redirect'],
                         env('VPN_LOOPBACK_IP') + ':' + str(port('VPN_MTPROTO_DD_PORT')))
        for outbound, backend in zip(result['outbounds'][-3:],
                                     (port('VPN_MTPROTO_PORT'), port('VPN_TELEGRAM_SOCKS_PORT'),
                                      port('VPN_MTPROTO_DD_PORT'))):
            self.assertEqual(outbound['settings']['finalRules'], [
                {'action': 'allow', 'network': 'tcp', 'ip': [env('VPN_LOOPBACK_IP') + '/32'], 'port': str(backend)},
                {'action': 'block'},
            ])
        repeated = routes.transform(result)
        self.assertEqual(repeated, result)
        self.assertIsNot(repeated, result)

    def test_exact_legacy_pair_is_extended_without_changing_existing_bytes(self):
        legacy = routes.transform(self.runtime())
        legacy['routing']['rules'].pop(5)
        legacy['outbounds'].pop()
        for rule in legacy['routing']['rules'][3:5]:
            rule['enabled'] = True
        legacy['outbounds'].append({'tag': 'later-unrelated-handler', 'protocol': 'blackhole'})
        before = copy.deepcopy(legacy)
        desired = routes.transform(legacy)
        self.assertEqual(legacy, before)
        self.assertEqual(desired['inbounds'], before['inbounds'])
        self.assertEqual(desired['outbounds'][:-1], before['outbounds'])
        self.assertEqual(desired['outbounds'][-1], routes.expected_outbounds()[-1])
        self.assertEqual(desired['routing']['rules'][:5], before['routing']['rules'][:5])
        self.assertEqual(desired['routing']['rules'][6:], before['routing']['rules'][5:])
        self.assertEqual(desired['routing']['rules'][5], routes.expected_rules(routes.eligible_inbound_tags(legacy))[-1])
        self.assertEqual(routes.transform(desired), desired)

    def test_api_only_panel_template_uses_validated_runtime_inputs(self):
        runtime = self.runtime()
        template = copy.deepcopy(runtime)
        template['inbounds'] = template['inbounds'][:1]
        for rule in template['routing']['rules']:
            rule['enabled'] = True
        before = copy.deepcopy(template)
        candidate, panel = routes.candidates(runtime, template)
        self.assertEqual(template, before)
        self.assertEqual(panel['inbounds'], before['inbounds'])
        self.assertEqual(routes.normalized_routing(panel['routing']), candidate['routing'])
        self.assertEqual(panel['outbounds'], candidate['outbounds'])
        self.assertEqual(routes.candidates(candidate, panel), (candidate, panel))
        template['outbounds'][0]['protocol'] = 'blackhole'
        with self.assertRaisesRegex(RuntimeError, 'outbounds differ'):
            routes.candidates(runtime, template)

    def test_missing_auth_duplicate_tags_and_modified_global_blocks_fail_closed(self):
        for index, setting in ((1, 'clients'), (2, 'clients'), (3, 'accounts'),
                               (4, 'accounts'), (5, 'accounts'), (6, 'peers')):
            config = self.runtime()
            config['inbounds'][index]['settings'][setting] = []
            if index == 2:
                config['inbounds'][index]['settings'].pop('password')
            before = copy.deepcopy(config)
            with self.assertRaisesRegex(RuntimeError, 'authentication'):
                routes.transform(config)
            self.assertEqual(config, before)
        config = self.runtime()
        config['inbounds'][1]['tag'] = 'api'
        with self.assertRaisesRegex(RuntimeError, 'inbound tag'):
            routes.transform(config)
        for index in range(len(routes.LEADING_RULES)):
            config = self.runtime()
            config['routing']['rules'][index]['enabled'] = False
            with self.assertRaisesRegex(RuntimeError, 'blocks have changed'):
                routes.transform(config)

    def test_partial_or_broadened_existing_exception_is_never_overwritten(self):
        baseline = routes.transform(self.runtime())
        variants = []
        partial = copy.deepcopy(baseline)
        partial['outbounds'].pop()
        variants.append(partial)
        public = copy.deepcopy(baseline)
        public['routing']['rules'][3].pop('ip')
        variants.append(public)
        udp = copy.deepcopy(baseline)
        udp['routing']['rules'][3]['network'] = 'tcp,udp'
        variants.append(udp)
        redirected = copy.deepcopy(baseline)
        redirected['outbounds'][-1]['settings']['redirect'] = env('VPN_TEST_ADDRESS_D') + ':' + str(port('VPN_MTPROTO_DD_PORT'))
        variants.append(redirected)
        moved = copy.deepcopy(baseline)
        moved['routing']['rules'][2:4] = list(reversed(moved['routing']['rules'][2:4]))
        variants.append(moved)
        for variant in variants:
            before = copy.deepcopy(variant)
            with self.assertRaises(RuntimeError):
                routes.transform(variant)
            self.assertEqual(variant, before)

    def test_existing_auto_updater_preserves_validated_local_routes(self):
        runtime = self.runtime()
        runtime['inbounds'][1]['tag'] = variant.INBOUND
        runtime['inbounds'][1]['streamSettings'] = {'network': 'tcp', 'security': 'none'}
        runtime['inbounds'][1]['listen'] = env('VPN_LOOPBACK_IP')
        runtime['api'] = {'services': ['HandlerService', 'RoutingService']}
        runtime['routing']['rules'][-1] = copy.deepcopy(variant.OLD_RULE)
        local = routes.transform(runtime)
        updated = variant.transform(local)
        self.assertEqual(updated['inbounds'], local['inbounds'])
        self.assertEqual(updated['routing']['rules'][3:5], local['routing']['rules'][3:5])
        self.assertEqual(updated['routing']['rules'][-2:], [variant.VARIANT_RULE, variant.OLD_RULE])
        self.assertEqual(variant.transform(updated), updated)
        changed = copy.deepcopy(local)
        changed['routing']['rules'][3].pop('ip')
        with self.assertRaises(RuntimeError):
            variant.transform(changed)


if __name__ == '__main__':
    unittest.main()
