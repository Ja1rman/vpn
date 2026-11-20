"""Checks for private, pinned and additive MTProto installation."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import install_mtproto as installer


def credentials(key='11'):
    domain = 'yandex.ru'
    return {'secret': 'ee' + key * 16 + domain.encode().hex(), 'domain': domain}


class MtprotoInstallationTests(unittest.TestCase):
    def test_config_uses_one_auto_pool_without_direct_fallback(self):
        config = tomllib.loads(installer.config_text(credentials()))
        self.assertEqual(config['network']['proxies'], [expand('socks5://${VPN_LOOPBACK_IP}:${VPN_FAILOVER_SOCKS_PORT}')])
        self.assertEqual(config['bind-to'], expand('${VPN_BIND_IP}:${VPN_MTPROTO_PORT}'))
        self.assertEqual(config['public-ipv4'], env('VPN_ENTRY_ADDRESS'))
        self.assertEqual(config['prefer-ip'], 'only-ipv4')
        self.assertFalse(config['debug'])
        self.assertIn('User=vpn-mtproto\n', installer.unit_text())
        self.assertIn('ExecStart=/opt/vpn-mtproto/mtg run /etc/vpn-mtproto/config.toml\n', installer.unit_text())

    def test_secrets_allow_access_metadata_and_reject_wrong_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.json'
            value = dict(credentials(), server=env('VPN_ENTRY_ADDRESS'), port=env_port('VPN_MTPROTO_PORT'), links={'telegram': 'private'})
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            self.assertEqual(installer.read_secrets(path)['secret'], value['secret'])
            value['domain'] = 'example.com'
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                installer.read_secrets(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_secrets(path)

    def test_release_checksum_and_archive_member_are_validated(self):
        binary = bytearray(64)
        binary[:6], binary[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'release.tar.gz'
            for member_name in ('mtg', '../mtg'):
                with self.subTest(member_name=member_name):
                    with tarfile.open(archive, 'w:gz') as stream:
                        member = tarfile.TarInfo(member_name)
                        member.size = len(binary)
                        stream.addfile(member, io.BytesIO(binary))
                    with self.assertRaisesRegex(RuntimeError, 'checksum'):
                        installer.read_binary(archive)
                    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
                    with patch.object(installer, 'ARCHIVE_SHA256', expected):
                        if member_name == 'mtg':
                            self.assertEqual(installer.read_binary(archive), bytes(binary))
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                                installer.read_binary(archive)

    def test_write_modes_are_exact_under_private_umask(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(installer.os, 'fchown'):
            previous = os.umask(0o077)
            try:
                for mode in (0o755, 0o640, 0o644):
                    path = Path(directory) / str(mode)
                    installer.write_new(path, b'test', mode)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                with self.assertRaises(FileExistsError):
                    installer.write_new(path, b'replacement', mode)
                self.assertEqual(path.read_bytes(), b'test')
            finally:
                os.umask(previous)

    def test_existing_identical_installation_is_not_restarted_or_rotated(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            runtime, config_directory = root / 'opt', root / 'etc'
            paths = {'RUNTIME': runtime, 'CONFIG_DIRECTORY': config_directory,
                     'BINARY': runtime / 'mtg', 'CONFIG': config_directory / 'config.toml',
                     'UNIT_PATH': root / 'vpn-mtproto.service'}
            for key, value in paths.items():
                stack.enter_context(patch.object(installer, key, value))
            runtime.mkdir(mode=0o755)
            config_directory.mkdir(mode=0o750)
            payload = {paths['BINARY']: (b'pinned-binary', 0o755),
                       paths['CONFIG']: (installer.config_text(credentials()).encode(), 0o640),
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
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
            stack.enter_context(patch.object(installer, 'check_listener'))
            secret_reader = stack.enter_context(patch.object(installer, 'read_secrets', return_value=credentials()))
            stack.enter_context(patch.object(installer, 'read_binary', return_value=b'pinned-binary'))
            command = stack.enter_context(patch.object(installer, 'command', return_value=b''))
            result = installer.install(root / 'archive', root / 'secrets')
            self.assertTrue(result['already_installed'])
            command.assert_called_once_with('systemctl', 'is-active', '--quiet', 'vpn-mtproto.service')
            command.reset_mock()
            secret_reader.return_value = credentials('22')
            with self.assertRaisesRegex(RuntimeError, 'different MTProto installation'):
                installer.install(root / 'archive', root / 'secrets')
            command.assert_not_called()
            self.assertEqual(paths['CONFIG'].read_bytes(), payload[paths['CONFIG']][0])


if __name__ == '__main__':
    unittest.main()
