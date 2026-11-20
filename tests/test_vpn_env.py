import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
import vpn_env


class NetworkEnvironment(unittest.TestCase):
    def test_individual_endpoint_survives_runtime_bundle_without_copying_secrets(self):
        expected_port = str(vpn_env.port('VPN_TEST_VLESS_PORT'))
        with patch.object(vpn_env, 'environment_paths', return_value=[]), patch.dict(
                os.environ, {'VPN_STANDALONE_PORT': expected_port,
                             'VPN_NEW_HOST_ADDRESS': 'new.example.test',
                             'VPN_TELEGRAM_SOCKS_PASSWORD': 'private-fixture'}, clear=True):
            values = vpn_env.configured_values()
            self.assertEqual(values['VPN_STANDALONE_PORT'], expected_port)
            self.assertEqual(values['VPN_NEW_HOST_ADDRESS'], 'new.example.test')
            self.assertNotIn('VPN_TELEGRAM_SOCKS_PASSWORD', values)

    def test_precedence_typed_json_and_unrelated_template_variables(self):
        actual_port = vpn_env.port('VPN_TEST_VLESS_PORT')
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / 'local.json'
            runtime = Path(directory) / 'runtime.json'
            local.write_text(json.dumps({'VPN_STANDALONE_PORT': actual_port,
                                         'VPN_HOST_ADDRESS': 'old.example.test'}))
            runtime.write_text(json.dumps({'VPN_HOST_ADDRESS': 'runtime.example.test'}))
            values = {'VPN_ENDPOINTS_JSON': json.dumps({'VPN_HOST_ADDRESS': 'ci.example.test'}),
                      'VPN_HOST_ADDRESS': 'override.example.test',
                      'VPN_SELECTED_PORTS': json.dumps([actual_port])}
            with patch.object(vpn_env, 'environment_paths', return_value=[local, runtime]), \
                    patch.dict(os.environ, values, clear=True):
                resolved = vpn_env.resolve({'address': '${VPN_HOST_ADDRESS}',
                                            'port': '${VPN_STANDALONE_PORT}',
                                            'ports': '${VPN_SELECTED_PORTS}'})
                self.assertEqual(resolved, {'address': 'override.example.test',
                                            'port': actual_port, 'ports': [actual_port]})
                self.assertIs(type(resolved['port']), int)
                self.assertEqual(vpn_env.expand('${VPN_HOST_ADDRESS} $host {{ $labels.host }}'),
                                 'override.example.test $host {{ $labels.host }}')

    def test_missing_and_invalid_ports_fail_before_deployment(self):
        with patch.object(vpn_env, 'environment_paths', return_value=[]), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'VPN_REQUIRED_PORT'):
                vpn_env.port('VPN_REQUIRED_PORT')
            for invalid in (True, 0, 65536, 'http', '-1'):
                with self.subTest(invalid=invalid), patch.dict(
                        os.environ, {'VPN_ENDPOINTS_JSON': json.dumps({'VPN_REQUIRED_PORT': invalid})}):
                    with self.assertRaisesRegex(ValueError, 'VPN_REQUIRED_PORT'):
                        vpn_env.port('VPN_REQUIRED_PORT')


if __name__ == '__main__':
    unittest.main()
