"""Safety and authentication contracts for the independent Telegram frontend."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import install_telegram_socks as installer


def credentials():
    return {'username': 'telegram-test', 'password': secrets.token_urlsafe(32)}


def settings():
    return installer.Endpoints(env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'), env('VPN_ENTRY_ADDRESS'),
                               env_port('VPN_TELEGRAM_SOCKS_PORT'), env_port('VPN_FAILOVER_SOCKS_PORT'),
                               env_port('VPN_MTPROTO_PORT'), env_port('VPN_MTPROTO_PUBLIC_PORT'))


class TelegramSocksInstallationTests(unittest.TestCase):
    def test_password_required_and_single_auto_upstream_without_sniffing(self):
        access, endpoints = credentials(), settings()
        config = json.loads(installer.config_text(access, endpoints))
        self.assertEqual(len(config['inbounds']), 2)
        inbound = config['inbounds'][0]
        self.assertEqual(inbound['listen'], endpoints.bind)
        self.assertEqual(inbound['port'], endpoints.port)
        self.assertEqual(inbound['settings'], {'auth': 'password', 'udp': False,
                                              'accounts': [{'user': access['username'], 'pass': access['password']}]})
        self.assertEqual(inbound['sniffing'], {'enabled': False})
        self.assertEqual(config['outbounds'][0], {'tag': 'vpn-auto', 'protocol': 'socks',
                                                 'settings': {'servers': [{'address': endpoints.loopback,
                                                                          'port': endpoints.pool_port}]}})
        self.assertNotIn('api', config)

    def test_mtproto_is_fixed_tcp_and_freedom_is_never_a_default_or_catchall(self):
        endpoints = settings()
        config = json.loads(installer.config_text(credentials(), endpoints))
        tunnel = config['inbounds'][1]
        self.assertEqual(tunnel, {'tag': 'mtproto-tunnel', 'listen': endpoints.bind,
                                 'port': endpoints.mtproto_public_port, 'protocol': 'tunnel',
                                 'settings': {'address': endpoints.loopback, 'port': endpoints.mtproto_port,
                                              'network': 'tcp', 'followRedirect': False},
                                 'sniffing': {'enabled': False}})
        self.assertEqual(config['outbounds'][0]['tag'], 'vpn-auto')
        freedom = [outbound for outbound in config['outbounds'] if outbound['protocol'] == 'freedom']
        self.assertEqual(freedom, [{'tag': 'mtproto-loopback', 'protocol': 'freedom',
                                    'settings': {'redirect': f'{endpoints.loopback}:{endpoints.mtproto_port}'}}])
        rules = config['routing']['rules']
        self.assertEqual([rule for rule in rules if rule['outboundTag'] == freedom[0]['tag']],
                         [{'type': 'field', 'inboundTag': ['mtproto-tunnel'], 'outboundTag': 'mtproto-loopback'}])
        self.assertEqual(rules[-1], {'type': 'field', 'inboundTag': ['telegram-socks'], 'outboundTag': 'vpn-auto'})

    def test_private_credentials_validation_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'credentials.json'
            value = credentials()
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            self.assertEqual(installer.read_secrets(path), value)
            alias = path.with_name('alias.json')
            alias.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_secrets(alias)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_secrets(path)
            path.chmod(0o600)
            for change in ({'password': 'short'}, {'password': '\n' + value['password']},
                           {'username': 'bad\nname'}, {'user': 'another-name'}):
                path.write_text(json.dumps(value | change))
                with self.assertRaises(RuntimeError):
                    installer.read_secrets(path)

    def test_systemd_is_independent_unprivileged_and_has_no_secrets(self):
        unit = installer.unit_text()
        self.assertIn('User=vpn-telegram-socks\n', unit)
        self.assertIn('ExecStart=/opt/vpn-telegram-socks/xray run -config /etc/vpn-telegram-socks/config.json\n', unit)
        self.assertIn('After=network-online.target vpn-failover-pool.service\n', unit)
        self.assertNotIn('BindsTo=', unit)
        self.assertNotIn('Requires=', unit)
        self.assertNotIn('restart vpn-', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertIn('ProtectSystem=strict\n', unit)

    def test_read_exact_handles_fragmented_auth_replies(self):
        class Fragmented:
            def __init__(self):
                self.parts = iter((b'\x05', b'\x02', b''))

            def recv(self, count):
                return next(self.parts)

        connection = Fragmented()
        self.assertEqual(installer.read_exact(connection, 2), b'\x05\x02')
        with self.assertRaisesRegex(RuntimeError, 'closed connection'):
            installer.read_exact(connection, 1)

    def test_private_config_is_never_printed_by_failed_daemon_check(self):
        result = type('Result', (), {'returncode': 1, 'stdout': b'',
                                      'stderr': b'sensitive config contents'})()
        with patch.object(installer.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, '^Telegram SOCKS installation command failed: xray$'):
                installer.command('xray', 'run', '-test')

    def test_write_is_exclusive_and_keeps_exact_modes_under_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(installer.os, 'fchown'):
            old_umask = os.umask(0o077)
            try:
                for mode in (0o755, 0o640, 0o644):
                    path = Path(temporary) / str(mode)
                    installer.write_new(path, b'original', mode)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                    with self.assertRaises(FileExistsError):
                        installer.write_new(path, b'replacement', mode)
                    self.assertEqual(path.read_bytes(), b'original')
            finally:
                os.umask(old_umask)

    def test_identical_install_is_not_restarted_and_changed_password_is_refused(self):
        access, endpoints = credentials(), settings()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, config_directory = root / 'opt', root / 'etc'
            paths = {'RUNTIME': runtime, 'CONFIG_DIRECTORY': config_directory,
                     'BINARY': runtime / 'xray', 'CONFIG': config_directory / 'config.json',
                     'UNIT_PATH': root / 'vpn-telegram-socks.service'}
            for name, path in paths.items():
                stack.enter_context(patch.object(installer, name, path))
            runtime.mkdir(mode=0o755)
            config_directory.mkdir(mode=0o750)
            payload = {paths['BINARY']: (b'existing-xray', 0o755),
                       paths['CONFIG']: (installer.config_text(access, endpoints).encode(), 0o640),
                       paths['UNIT_PATH']: (installer.unit_text().encode(), 0o644)}
            for path, (value, mode) in payload.items():
                path.write_bytes(value)
                path.chmod(mode)
            real_lstat = Path.lstat

            def root_owned(path):
                fields = list(real_lstat(path))
                fields[4] = 0
                fields[5] = 123 if path in (config_directory, paths['CONFIG']) else 0
                return os.stat_result(fields)

            stack.enter_context(patch.object(Path, 'lstat', root_owned))
            stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=endpoints))
            secret_reader = stack.enter_context(patch.object(installer, 'read_secrets', return_value=access))
            stack.enter_context(patch.object(installer, 'read_binary', return_value=b'existing-xray'))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
            verifier = stack.enter_context(patch.object(installer, 'verify_listener'))
            command = stack.enter_context(patch.object(installer, 'command', return_value=b''))
            self.assertTrue(installer.install(root / 'private')['already_installed'])
            command.assert_called_once_with('systemctl', 'is-active', '--quiet', installer.UNIT)
            verifier.assert_called_once_with(access, endpoints)
            command.reset_mock()
            secret_reader.return_value = access | {'password': secrets.token_urlsafe(32)}
            with self.assertRaisesRegex(RuntimeError, 'refusing to overwrite'):
                installer.install(root / 'private')
            command.assert_not_called()
            self.assertEqual(paths['CONFIG'].read_bytes(), payload[paths['CONFIG']][0])


if __name__ == '__main__':
    unittest.main()
