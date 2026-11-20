"""Independent reserve credentials, direct paths and additive install refusal tests."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import install_telegram_reserve as installer
import deploy_telegram_reserve as deployer


def credentials():
    return {'scope': 'netherlands-reserve-fresh', 'username': 'fresh_' + secrets.token_hex(4),
            'password': secrets.token_urlsafe(36), 'dd_key': secrets.token_hex(16),
            'ee_key': secrets.token_hex(16), 'domain': 'cover.example'}


class ReserveTests(unittest.TestCase):
    def test_all_backends_loopback_direct_and_no_entry_dependency(self):
        value, settings = credentials(), installer.endpoints()
        socks = installer.socks_config(value, settings)
        self.assertEqual(socks['inbounds'][0]['listen'], settings.loopback)
        self.assertEqual(socks['inbounds'][0]['listen_port'], settings.socks)
        self.assertEqual(socks['outbounds'], [{'type': 'direct', 'tag': 'reserve-direct'}])
        self.assertEqual(socks['route']['rules'], [
            {'ip_is_private': True, 'action': 'reject'},
            {'ip_cidr': [settings.public + '/32'], 'action': 'reject'}])
        options = {}
        exec(installer.dd_config(value, settings), {}, options)
        self.assertIsNone(options['SOCKS5_HOST'])
        self.assertIsNone(options['SOCKS5_PORT'])
        self.assertEqual(options['LISTEN_ADDR_IPV4'], settings.loopback)
        self.assertEqual(options['MODES'], {'classic': False, 'secure': True, 'tls': False})
        ee = installer.ee_config(value, settings)
        self.assertIn('proxies = []\n', ee)
        self.assertIn('bind-to = "' + settings.loopback + ':' + str(settings.ee) + '"', ee)
        for role in installer.ROLES:
            unit = installer.unit_text(role)
            self.assertNotIn('vpn-failover', unit)
            self.assertNotIn('x-ui', unit)
            self.assertIn('CapabilityBoundingSet=\n', unit)
            self.assertIn('StandardError=null\n', unit)
        self.assertIn('RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n',
                      installer.unit_text('socks'))

    def test_fresh_credentials_and_access_are_stable_separate_and_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'reserve'
            path = deployer.prepare(folder)
            before = path.read_bytes()
            value = installer.read_credentials(path)
            self.assertNotEqual(value['dd_key'], value['ee_key'])
            self.assertEqual(deployer.prepare(folder).read_bytes(), before)
            for role in installer.ROLES:
                public = json.loads((folder / role / 'access.json').read_text())
                backend = json.loads((folder / role / 'backend-access.json').read_text())
                self.assertEqual(public['server'], env('VPN_NL_ADDRESS'))
                self.assertEqual(public['port'], port('VPN_NL_TELEGRAM_PUBLIC_PORT'))
                self.assertEqual(backend['server'], env('VPN_LOOPBACK_IP'))
                for filename in ('access.json', 'backend-access.json', 'access.md'):
                    self.assertEqual((folder / role / filename).stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn('user=', (folder / 'socks/access.md').read_text())
            self.assertNotIn('username=', (folder / 'socks/access.md').read_text())

    def test_no_reuse_of_legacy_or_equal_keys_and_no_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fresh.json'
            value = credentials()
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            self.assertEqual(installer.read_credentials(path), value)
            value['ee_key'] = value['dd_key']
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, 'independent'):
                installer.read_credentials(path)
            value = credentials()
            value['scope'] = 'entry'
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, 'specifically'):
                installer.read_credentials(path)
            link = path.with_name('link.json')
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_credentials(link)

    def test_protected_environment_restores_same_keys_and_refuses_rotation(self):
        value = credentials()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {'VPN_TELEGRAM_RESERVE_CREDENTIALS_JSON': json.dumps(value)}):
            folder = Path(temporary) / 'reserve'
            path = deployer.prepare(folder)
            self.assertEqual(installer.read_credentials(path), value)
            before = path.read_bytes()
            deployer.prepare(folder)
            self.assertEqual(path.read_bytes(), before)
            with patch.dict(os.environ, {'VPN_TELEGRAM_RESERVE_CREDENTIALS_JSON': json.dumps(credentials())}):
                with self.assertRaisesRegex(RuntimeError, 'refusing rotation'):
                    deployer.prepare(folder)
            self.assertEqual(path.read_bytes(), before)
            with patch.dict(os.environ, {'VPN_TELEGRAM_RESERVE_CREDENTIALS_JSON': 'invalid'}):
                with self.assertRaisesRegex(RuntimeError, 'valid JSON'):
                    deployer.prepare(folder)

    def test_public_port_migration_preserves_keys_and_backends_with_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'reserve'
            with patch.dict(os.environ, {'VPN_NL_TELEGRAM_PUBLIC_PORT': env('VPN_NL_RELAY_TLS_PORT')}):
                deployer.prepare(folder)
            credentials_before = (folder / 'credentials.json').read_bytes()
            backends_before = {role: (folder / role / 'backend-access.json').read_bytes()
                               for role in installer.ROLES}
            public_before = {role: (folder / role / 'access.json').read_bytes() for role in installer.ROLES}
            report = deployer.refresh_public_port(folder)
            self.assertEqual(report['updated_files'], len(installer.ROLES) * 2)
            backup = Path(report['backup'])
            for role in installer.ROLES:
                self.assertEqual((backup / role / 'access.json').read_bytes(), public_before[role])
                actual = json.loads((folder / role / 'access.json').read_text())
                original = json.loads(public_before[role])
                original['port'] = port('VPN_NL_TELEGRAM_PUBLIC_PORT')
                self.assertEqual(actual, original)
                self.assertEqual((folder / role / 'backend-access.json').read_bytes(), backends_before[role])
            self.assertEqual((folder / 'credentials.json').read_bytes(), credentials_before)
            self.assertTrue(deployer.refresh_public_port(folder)['already_current'])

    def test_reserve_asset_paths_and_units_stay_in_new_namespace(self):
        with patch.object(installer, 'read_sing_binary', return_value=b'sing'), \
                patch.object(installer.ee, 'read_binary', return_value=b'mtg'), \
                patch.object(installer.dd, 'read_assets', return_value={
                    installer.dd.SOURCE / 'mtprotoproxy.py': b'source',
                    installer.dd.SOCKS / 'socks.py': b'dependency',
                    installer.dd.MANIFEST: b'{}'}):
            files = installer.payload(None, None, None, None, credentials(), installer.endpoints())
        self.assertIn(installer.RUNTIME / 'dd/vendor/source/mtprotoproxy.py', files)
        self.assertIn(installer.RUNTIME / 'dd/vendor/pysocks/socks.py', files)
        for role in installer.ROLES:
            unit = files[installer.SYSTEMD / installer.UNITS[role]].decode()
            self.assertIn('User=' + installer.NAME + '\n', unit)
        self.assertTrue(all(path.is_relative_to(installer.RUNTIME)
                            or path.is_relative_to(installer.PRIVATE)
                            or path.name in installer.UNITS.values() for path in files))

    def test_conflicting_installation_is_refused_before_commands_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, private = root / 'runtime', root / 'private'
            runtime.mkdir()
            (runtime / 'unrelated').write_bytes(b'preserve')
            stack.enter_context(patch.object(installer, 'RUNTIME', runtime))
            stack.enter_context(patch.object(installer, 'PRIVATE', private))
            stack.enter_context(patch.object(installer, 'SYSTEMD', root / 'units'))
            stack.enter_context(patch.object(installer.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(installer, 'read_credentials', return_value=credentials()))
            stack.enter_context(patch.object(installer, 'payload', return_value={runtime / 'binary': b'new'}))
            stack.enter_context(patch.object(installer.dd, 'check_dependency'))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(os.getuid(), os.getgid())))
            command = stack.enter_context(patch.object(installer, 'command'))
            with self.assertRaises(OSError):
                installer.install(SimpleNamespace(credentials=None, sing_archive=None, ee_archive=None,
                                                   dd_archive=None, socks_wheel=None))
            self.assertEqual((runtime / 'unrelated').read_bytes(), b'preserve')
            self.assertFalse(private.exists())
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
