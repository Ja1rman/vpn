import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import install_auto_tls_frontend as auto
import install_xray_tls_frontends as frontend


class XrayTLSFrontendTests(unittest.TestCase):
    def runtime(self):
        config = {'inbounds': [], 'routing': {'rules': []}}
        for index, port in enumerate(frontend.PORTS.values()):
            config['inbounds'].append({'tag': f'in-{port}-tcp', 'port': port, 'protocol': 'vless',
                'listen': '0.0.0.0', 'settings': {'decryption': 'none', 'clients': [{'id': 'fixture'}]},
                'streamSettings': {'network': 'tcp', 'security': 'none'}})
            config['routing']['rules'].append({'type': 'field', 'inboundTag': [f'in-{port}-tcp'],
                'outboundTag': 'vpn-egress-pool' if index == 0 else f'fixture-out-{index}'})
        return config

    def test_four_public_tls_ports_preserve_routes_and_source(self):
        config = frontend.nginx_config()
        for public, backend in frontend.PORTS.items():
            self.assertIn(f'listen 0.0.0.0:{public} ssl;', config)
            self.assertIn(f'proxy_pass 127.0.0.1:{backend};', config)
        self.assertEqual(config.count('proxy_bind 127.0.0.1;'), 4)
        self.assertNotIn('127.0.0.2', config)
        self.assertIn('valid=30s', config)
        self.assertNotIn('proxy_protocol on;', config)
        frontend.validate_backends(self.runtime())

    def test_no_tls_or_vision_backend_is_silently_wrapped(self):
        for port in frontend.PORTS.values():
            config = self.runtime()
            selected = next(i for i in config['inbounds'] if i['port'] == port)
            selected['streamSettings']['security'] = 'reality'
            with self.assertRaisesRegex(RuntimeError, 'plain VLESS'):
                frontend.validate_backends(config)
        config = self.runtime()
        config['inbounds'][0]['settings']['clients'][0]['flow'] = 'xtls-rprx-vision'
        with self.assertRaisesRegex(RuntimeError, 'plain VLESS'):
            frontend.validate_backends(config)

    def test_shared_helper_import_does_not_rebind_auto_globals(self):
        self.assertEqual(auto.PORT, 33175)
        self.assertEqual(auto.SOURCE_IP, '127.0.0.2')
        self.assertIn('proxy_bind 127.0.0.2;', auto.nginx_config())
        unit = frontend.unit_text(996, 997)
        self.assertIn('--name vpn-xray-tls-frontends', unit)
        self.assertIn('--cap-drop=ALL', unit)
        self.assertIn('--user 996:997', unit)
        self.assertNotIn('vpn-auto-tls-frontend stop-container', unit)

    def test_missing_or_changed_catchall_refused(self):
        config = self.runtime()
        config['routing']['rules'].pop()
        with self.assertRaisesRegex(RuntimeError, 'unique existing catchall'):
            frontend.validate_backends(config)
        config = self.runtime()
        config['routing']['rules'][0]['outboundTag'] = 'other-pool'
        with self.assertRaisesRegex(RuntimeError, 'legacy pool'):
            frontend.validate_backends(config)


if __name__ == '__main__':
    unittest.main()
