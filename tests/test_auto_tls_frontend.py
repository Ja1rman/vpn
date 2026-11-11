import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import install_auto_tls_frontend as frontend
from enable_failover_variant import OLD_RULE, VARIANT_OUT, VARIANT_RULE


class AutoTLSFrontendTests(unittest.TestCase):
    def runtime(self):
        return {'inbounds': [{'tag': 'in-46738-tcp', 'protocol': 'vless', 'port': 46738,
                              'listen': '0.0.0.0', 'settings': {'decryption': 'none'},
                              'streamSettings': {'network': 'tcp', 'security': 'none',
                                                 'tcpSettings': {'header': {'type': 'none'}}}}],
                'outbounds': [copy.deepcopy(VARIANT_OUT)],
                'routing': {'rules': [copy.deepcopy(VARIANT_RULE), copy.deepcopy(OLD_RULE)]}}

    def test_existing_raw_backend_is_required(self):
        self.assertEqual(frontend.validate_backend(self.runtime())[0],
                         ('vpn-failover-egress-pool', 'vpn-failover-source-127-0-0-2'))
        for changes in ({'network': 'xhttp'}, {'security': 'reality'},
                        {'tcpSettings': {'header': {'type': 'http'}}},
                        {'sockopt': {'acceptProxyProtocol': True}}):
            config = self.runtime()
            config['inbounds'][0]['streamSettings'].update(changes)
            with self.assertRaisesRegex(RuntimeError, 'raw VLESS'):
                frontend.validate_backend(config)

    def test_catchall_cannot_eclipse_auto_source(self):
        config = self.runtime()
        config['routing']['rules'].reverse()
        with self.assertRaisesRegex(RuntimeError, 'routing is unexpected'):
            frontend.validate_backend(config)

    def test_stream_flags_support_static_and_dynamic_nginx(self):
        self.assertEqual(frontend.stream_module('--with-stream --with-stream_ssl_module'), '')
        self.assertEqual(frontend.stream_module('--with-stream=dynamic --with-stream_ssl_module '
                                                '--modules-path=/usr/lib/nginx/modules'),
                         'load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n')
        with self.assertRaisesRegex(RuntimeError, 'no stream SSL support'):
            frontend.stream_module('--with-stream')

    def test_unit_owns_one_container_and_does_not_modify_subscription(self):
        unit = frontend.unit_text(996, 997)
        self.assertIn('--name vpn-auto-tls-frontend', unit)
        self.assertIn('--user 996:997', unit)
        self.assertIn('--cap-drop=ALL', unit)
        self.assertIn('source=/etc/vpn-failover-subscription,target=/etc/vpn-subscription,readonly', unit)
        self.assertNotIn('restart vpn-', unit)
        config = frontend.nginx_config()
        self.assertIn('listen 0.0.0.0:33175 ssl;', config)
        self.assertIn('proxy_pass 127.0.0.1:46738;', config)
        self.assertIn('proxy_bind 127.0.0.2;', config)
        self.assertNotIn('proxy_protocol on;', config)

    def test_missing_container_is_not_stopped_by_name(self):
        with patch.object(frontend, 'CIDFILE') as cidfile, patch.object(frontend, 'command') as command:
            cidfile.exists.return_value = False
            frontend.stop_container()
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
