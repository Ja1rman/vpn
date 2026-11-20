import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import install_auto_tls_frontend as frontend
from enable_failover_variant import OLD_RULE, VARIANT_OUT, VARIANT_RULE


class AutoTLSFrontendTests(unittest.TestCase):
    def runtime(self):
        return {'inbounds': [{'tag': expand('in-${VPN_VLESS_AUTH_PORT}-tcp'), 'protocol': 'vless', 'port': env_port('VPN_VLESS_AUTH_PORT'),
                              'listen': env('VPN_BIND_IP'), 'settings': {'decryption': 'none'},
                              'streamSettings': {'network': 'tcp', 'security': 'none',
                                                 'tcpSettings': {'header': {'type': 'none'}}}}],
                'outbounds': [copy.deepcopy(VARIANT_OUT)],
                'routing': {'rules': [copy.deepcopy(VARIANT_RULE), copy.deepcopy(OLD_RULE)]}}

    def test_existing_raw_backend_is_required(self):
        self.assertEqual(frontend.validate_backend(self.runtime())[0],
                         ('vpn-failover-egress-pool', 'vpn-failover-source-' + env('VPN_AUTO_SOURCE_IP').replace('.', '-')))
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
        self.assertIn(expand('listen ${VPN_BIND_IP}:${VPN_AUTO_TLS_PORT} ssl;'), config)
        self.assertIn(expand('proxy_pass ${VPN_LOOPBACK_IP}:${VPN_VLESS_AUTH_PORT};'), config)
        self.assertIn(expand('proxy_bind ${VPN_AUTO_SOURCE_IP};'), config)
        self.assertNotIn('proxy_protocol on;', config)

    def test_missing_container_is_not_stopped_by_name(self):
        with patch.object(frontend, 'CIDFILE') as cidfile, patch.object(frontend, 'command') as command:
            cidfile.exists.return_value = False
            frontend.stop_container()
            command.assert_not_called()

    def test_private_helper_refresh_preserves_service_files_and_refuses_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, config = root / 'runtime', root / 'config'
            runtime.mkdir(mode=0o700)
            config.mkdir(mode=0o700)
            unit, nginx, application = root / 'service', config / 'nginx.conf', runtime / 'helper.py'
            frozen = {unit: (b'original unit\n', 0o644), nginx: (b'original nginx\n', 0o644)}
            for path, (data, mode) in frozen.items():
                frontend.write_new(path, data, mode)
            frontend.write_new(application, b'previous = True\n', 0o600)
            helpers = {application: (b'updated = True\n', 0o600), **frontend.environment_payload(runtime)}
            original_stat = Path.stat

            def root_metadata(path, **kwargs):
                fields = list(original_stat(path, **kwargs))
                fields[4:6] = (0, 0)
                return os.stat_result(fields)

            identity = Mock(return_value=(b'fixture-pid', 'fixture-container', 'fixture-container-pid'))
            verify = Mock()
            with patch.object(Path, 'stat', root_metadata), patch.object(frontend.os, 'chown'), \
                    patch.object(frontend, 'command') as command:
                self.assertTrue(frontend.refresh_runtime_helpers(runtime, config, frozen, helpers, identity, verify))
                self.assertFalse(frontend.refresh_runtime_helpers(runtime, config, frozen, helpers, identity, verify))
                for path, (data, mode) in helpers.items():
                    self.assertEqual(path.read_bytes(), data)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                for path, (data, _) in frozen.items():
                    self.assertEqual(path.read_bytes(), data)
                command.assert_not_called()
                unit.write_bytes(b'edited unit\n')
                with self.assertRaisesRegex(RuntimeError, 'configuration or unit differs'):
                    frontend.refresh_runtime_helpers(runtime, config, frozen, helpers, identity, verify)
                self.assertEqual(application.read_bytes(), helpers[application][0])

    def test_helper_refresh_rolls_back_when_running_identity_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, config = root / 'runtime', root / 'config'
            runtime.mkdir(mode=0o700)
            config.mkdir(mode=0o700)
            application = runtime / 'helper.py'
            original = b'previous = True\n'
            frontend.write_new(application, original, 0o600)
            helpers = {application: (b'updated = True\n', 0o600), **frontend.environment_payload(runtime)}
            original_stat = Path.stat

            def root_metadata(path, **kwargs):
                fields = list(original_stat(path, **kwargs))
                fields[4:6] = (0, 0)
                return os.stat_result(fields)

            identity = Mock(side_effect=['original-identity', 'changed-identity'])
            with patch.object(Path, 'stat', root_metadata), patch.object(frontend.os, 'chown'), \
                    patch.object(frontend, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                    frontend.refresh_runtime_helpers(runtime, config, {}, helpers, identity, Mock())
                command.assert_not_called()
            self.assertEqual(application.read_bytes(), original)
            self.assertFalse((runtime / 'vpn.env.json').exists())
            self.assertFalse((runtime / 'vpn_env.py').exists())

    def test_installed_helper_imports_with_only_its_private_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            payload = {runtime / 'install_auto_tls_frontend.py': (Path(frontend.__file__).read_bytes(), 0o600),
                       **frontend.environment_payload(runtime)}
            for path, (data, mode) in payload.items():
                frontend.write_new(path, data, mode)
            result = subprocess.run([sys.executable, '-B', str(runtime / 'install_auto_tls_frontend.py'), '--help'],
                                    env={key: value for key, value in os.environ.items() if not key.startswith('VPN_')},
                                    cwd=runtime, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
