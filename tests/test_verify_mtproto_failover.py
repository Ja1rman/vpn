import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import verify_mtproto_failover as verify


class IsolatedMtprotoFailoverTest(unittest.TestCase):
    def pool(self):
        return {
            'inbounds': [
                {'tag': 'pool-socks', 'listen': env('VPN_LOOPBACK_IP'), 'port': env_port('VPN_FAILOVER_SOCKS_PORT')},
                {'tag': 'api', 'listen': env('VPN_LOOPBACK_IP'), 'port': env_port('VPN_AUTO_API_PORT')},
                {'tag': 'pool-ip-sniff', 'listen': env('VPN_LOOPBACK_IP'), 'port': env_port('VPN_AUTO_SNIFF_PORT')}],
            'outbounds': [
                {'tag': 'pool-site-' + str(i), 'protocol': 'vless',
                 'settings': {'address': env('VPN_TEST_ADDRESS_' + chr(ord('A') + i - 1)),
                              'port': env_port('VPN_EXIT_TLS_PORT'), 'id': 'private-placeholder'},
                 'streamSettings': {'security': 'reality'}} for i in range(1, 4)] + [
                {'tag': 'vpn-auto-sniff-hop', 'protocol': 'socks',
                 'settings': {'address': env('VPN_LOOPBACK_IP'), 'port': env_port('VPN_AUTO_SNIFF_PORT')}},
                {'tag': 'vpn-auto-ru-direct', 'protocol': 'freedom', 'settings': {'privateBlock': True}}],
            'routing': {'rules': [{'domain': ['regexp:ru'], 'outboundTag': 'vpn-auto-ru-direct'}],
                        'balancers': [{'selector': ['pool-site-' + str(i)]} for i in range(1, 4)]},
            'observatory': {'subjectSelector': ['pool-site-'], 'probeInterval': '10s'},
            'log': {'access': 'none', 'loglevel': 'warning'},
        }

    def test_clone_isolates_all_listeners_and_two_failed_exits_without_changing_source_or_ru(self):
        source = self.pool()
        before = copy.deepcopy(source)
        ports = {'pool-socks': env_port('VPN_TEST_POOL_PORT'), 'api': env_port('VPN_TEST_API_PORT'), 'pool-ip-sniff': env_port('VPN_TEST_SNIFF_PORT')}
        result = verify.isolated_pool(source, 2, ports, [env_port('VPN_TEST_EXIT_A_PORT'), env_port('VPN_TEST_EXIT_B_PORT')])
        self.assertEqual(source, before)
        self.assertEqual({x['tag']: x['port'] for x in result['inbounds']}, ports)
        self.assertEqual([x['settings']['address'] for x in result['outbounds'][:3]],
                         [env('VPN_LOOPBACK_IP'), env('VPN_LOOPBACK_IP'), env('VPN_TEST_ADDRESS_C')])
        self.assertEqual([x['settings']['port'] for x in result['outbounds'][:3]], [env_port('VPN_TEST_EXIT_A_PORT'), env_port('VPN_TEST_EXIT_B_PORT'), env_port('VPN_EXIT_TLS_PORT')])
        self.assertEqual(result['outbounds'][3]['settings']['port'], env_port('VPN_TEST_SNIFF_PORT'))
        self.assertEqual(result['outbounds'][4], before['outbounds'][4])
        self.assertEqual(result['routing'], before['routing'])
        self.assertEqual(result['observatory']['probeInterval'], '1s')

    def test_all_failed_supports_legacy_vnext_endpoint_shape(self):
        source = self.pool()
        third = source['outbounds'][2]
        third['settings'] = {'vnext': [third['settings']]}
        result = verify.isolated_pool(source, 3, {'pool-socks': env_port('VPN_TEST_POOL_PORT'), 'api': env_port('VPN_TEST_API_PORT'),
                                                 'pool-ip-sniff': env_port('VPN_TEST_SNIFF_PORT')}, [env_port('VPN_TEST_EXIT_A_PORT'), env_port('VPN_TEST_EXIT_B_PORT'), env_port('VPN_TEST_EXIT_C_PORT')])
        self.assertEqual(result['outbounds'][2]['settings']['vnext'][0]['address'], env('VPN_LOOPBACK_IP'))
        self.assertEqual(result['outbounds'][2]['settings']['vnext'][0]['port'], env_port('VPN_TEST_EXIT_C_PORT'))
        self.assertEqual(third['settings']['vnext'][0]['address'], env('VPN_TEST_ADDRESS_C'))

    def test_unknown_listener_or_unencrypted_site_refuses(self):
        source = self.pool()
        source['inbounds'].append({'tag': 'unexpected', 'listen': env('VPN_LOOPBACK_IP'), 'port': env_port('VPN_TEST_UNEXPECTED_PORT')})
        with self.assertRaises(RuntimeError):
            verify.isolated_pool(source, 2, {}, [env_port('VPN_TEST_EXIT_A_PORT'), env_port('VPN_TEST_EXIT_B_PORT')])
        source = self.pool()
        source['outbounds'][0]['streamSettings']['security'] = 'none'
        with self.assertRaisesRegex(RuntimeError, 'encrypted VLESS'):
            verify.isolated_pool(source, 2, {'pool-socks': env_port('VPN_TEST_POOL_PORT'), 'api': env_port('VPN_TEST_API_PORT'),
                                            'pool-ip-sniff': env_port('VPN_TEST_SNIFF_PORT')}, [env_port('VPN_TEST_EXIT_A_PORT'), env_port('VPN_TEST_EXIT_B_PORT')])

    def test_toml_rewrites_only_bind_and_proxy_preserving_secret_and_other_settings(self):
        source = (expand('secret = "ee-private-fixture"\nbind-to = "${VPN_BIND_IP}:${VPN_MTPROTO_PORT}"\nconcurrency = 2048\n[network]\nprefer-ip = "only-ipv4"\nproxies = ["socks5://${VPN_LOOPBACK_IP}:${VPN_FAILOVER_SOCKS_PORT}"] # private upstream\n'))
        result = verify.isolated_mtg(source, env_port('VPN_TEST_VLESS_PORT'), env_port('VPN_TEST_POOL_PORT'))
        expected = source.replace(expand('bind-to = "${VPN_BIND_IP}:${VPN_MTPROTO_PORT}"'), expand('bind-to = "${VPN_LOOPBACK_IP}:${VPN_TEST_VLESS_PORT}"')).replace(
            expand('proxies = ["socks5://${VPN_LOOPBACK_IP}:${VPN_FAILOVER_SOCKS_PORT}"] # private upstream'),
            expand('proxies = ["socks5://${VPN_LOOPBACK_IP}:${VPN_TEST_POOL_PORT}"]'))
        self.assertEqual(result, expected)

    def test_toml_unknown_upstream_and_multiline_proxy_list_refuse(self):
        for proxies in (expand('["socks5://${VPN_LOOPBACK_IP}:${VPN_BALANCER_SOCKS_PORT}"]'), expand('[\n"socks5://${VPN_LOOPBACK_IP}:${VPN_FAILOVER_SOCKS_PORT}"\n]')):
            with self.assertRaises(RuntimeError):
                verify.isolated_mtg(expand('bind-to="${VPN_BIND_IP}:${VPN_MTPROTO_PORT}"\n[network]\nproxies = ')+proxies+'\n',
                                    env_port('VPN_TEST_VLESS_PORT'), env_port('VPN_TEST_POOL_PORT'))


if __name__ == '__main__':
    unittest.main()
