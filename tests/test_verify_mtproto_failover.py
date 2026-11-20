import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import verify_mtproto_failover as verify


class IsolatedMtprotoFailoverTest(unittest.TestCase):
    def pool(self):
        return {
            'inbounds': [
                {'tag': 'pool-socks', 'listen': '127.0.0.1', 'port': 11092},
                {'tag': 'api', 'listen': '127.0.0.1', 'port': 11093},
                {'tag': 'pool-ip-sniff', 'listen': '127.0.0.1', 'port': 11094}],
            'outbounds': [
                {'tag': 'pool-site-' + str(i), 'protocol': 'vless',
                 'settings': {'address': '192.0.2.' + str(i), 'port': 443, 'id': 'private-placeholder'},
                 'streamSettings': {'security': 'reality'}} for i in range(1, 4)] + [
                {'tag': 'vpn-auto-sniff-hop', 'protocol': 'socks',
                 'settings': {'address': '127.0.0.1', 'port': 11094}},
                {'tag': 'vpn-auto-ru-direct', 'protocol': 'freedom', 'settings': {'privateBlock': True}}],
            'routing': {'rules': [{'domain': ['regexp:ru'], 'outboundTag': 'vpn-auto-ru-direct'}],
                        'balancers': [{'selector': ['pool-site-' + str(i)]} for i in range(1, 4)]},
            'observatory': {'subjectSelector': ['pool-site-'], 'probeInterval': '10s'},
            'log': {'access': 'none', 'loglevel': 'warning'},
        }

    def test_clone_isolates_all_listeners_and_two_failed_exits_without_changing_source_or_ru(self):
        source = self.pool()
        before = copy.deepcopy(source)
        ports = {'pool-socks': 41001, 'api': 41002, 'pool-ip-sniff': 41003}
        result = verify.isolated_pool(source, 2, ports, [42001, 42002])
        self.assertEqual(source, before)
        self.assertEqual({x['tag']: x['port'] for x in result['inbounds']}, ports)
        self.assertEqual([x['settings']['address'] for x in result['outbounds'][:3]],
                         ['127.0.0.1', '127.0.0.1', '192.0.2.3'])
        self.assertEqual([x['settings']['port'] for x in result['outbounds'][:3]], [42001, 42002, 443])
        self.assertEqual(result['outbounds'][3]['settings']['port'], 41003)
        self.assertEqual(result['outbounds'][4], before['outbounds'][4])
        self.assertEqual(result['routing'], before['routing'])
        self.assertEqual(result['observatory']['probeInterval'], '1s')

    def test_all_failed_supports_legacy_vnext_endpoint_shape(self):
        source = self.pool()
        third = source['outbounds'][2]
        third['settings'] = {'vnext': [third['settings']]}
        result = verify.isolated_pool(source, 3, {'pool-socks': 41001, 'api': 41002,
                                                 'pool-ip-sniff': 41003}, [42001, 42002, 42003])
        self.assertEqual(result['outbounds'][2]['settings']['vnext'][0]['address'], '127.0.0.1')
        self.assertEqual(result['outbounds'][2]['settings']['vnext'][0]['port'], 42003)
        self.assertEqual(third['settings']['vnext'][0]['address'], '192.0.2.3')

    def test_unknown_listener_or_unencrypted_site_refuses(self):
        source = self.pool()
        source['inbounds'].append({'tag': 'unexpected', 'listen': '127.0.0.1', 'port': 12000})
        with self.assertRaises(RuntimeError):
            verify.isolated_pool(source, 2, {}, [42001, 42002])
        source = self.pool()
        source['outbounds'][0]['streamSettings']['security'] = 'none'
        with self.assertRaisesRegex(RuntimeError, 'encrypted VLESS'):
            verify.isolated_pool(source, 2, {'pool-socks': 41001, 'api': 41002,
                                            'pool-ip-sniff': 41003}, [42001, 42002])

    def test_toml_rewrites_only_bind_and_proxy_preserving_secret_and_other_settings(self):
        source = ('secret = "ee-private-fixture"\nbind-to = "0.0.0.0:8443"\n'
                  'concurrency = 2048\n[network]\nprefer-ip = "only-ipv4"\n'
                  'proxies = ["socks5://127.0.0.1:11092"] # private upstream\n')
        result = verify.isolated_mtg(source, 43001, 41001)
        expected = source.replace('bind-to = "0.0.0.0:8443"', 'bind-to = "127.0.0.1:43001"').replace(
            'proxies = ["socks5://127.0.0.1:11092"] # private upstream',
            'proxies = ["socks5://127.0.0.1:41001"]')
        self.assertEqual(result, expected)

    def test_toml_unknown_upstream_and_multiline_proxy_list_refuse(self):
        for proxies in ('["socks5://127.0.0.1:11090"]', '[\n"socks5://127.0.0.1:11092"\n]'):
            with self.assertRaises(RuntimeError):
                verify.isolated_mtg('bind-to="0.0.0.0:8443"\n[network]\nproxies = '+proxies+'\n',
                                    43001, 41001)


if __name__ == '__main__':
    unittest.main()
