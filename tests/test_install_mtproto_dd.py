"""Pinned dependencies, isolation and refusal contracts for the additive DD service."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import install_mtproto_dd as installer


def settings():
    return installer.Endpoints(env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'), env('VPN_ENTRY_ADDRESS'),
                               port('VPN_MTPROTO_DD_PORT'), port('VPN_FAILOVER_SOCKS_PORT'))


def ee_secret():
    key = secrets.token_bytes(16)
    return key.hex(), (b'\xee' + key + b'cover.example').hex()


def fixture_assets(root, member=None):
    archive, wheel = root / 'source.tar.gz', root / 'dependency.whl'
    with tarfile.open(archive, 'w:gz') as stream:
        info = member or tarfile.TarInfo('mtprotoproxy-' + installer.SOURCE_COMMIT + '/mtprotoproxy.py')
        body = b'"""Pinned source fixture."""\n'
        if info.isreg():
            info.size = len(body)
            stream.addfile(info, io.BytesIO(body))
        else:
            stream.addfile(info)
    with zipfile.ZipFile(wheel, 'w') as stream:
        stream.writestr('socks.py', '"""Pinned dependency fixture."""\n')
    return archive, wheel


class MtprotoDDInstallationTests(unittest.TestCase):
    def test_secure_only_auto_upstream_and_no_extra_listener(self):
        key, _ = ee_secret()
        endpoint = settings()
        config = {}
        exec(installer.config_text(key, endpoint), {}, config)
        self.assertEqual(config['USERS'], {'vpn': key})
        self.assertEqual(config['MODES'], {'classic': False, 'secure': True, 'tls': False})
        self.assertEqual((config['SOCKS5_HOST'], config['SOCKS5_PORT']),
                         (endpoint.loopback, endpoint.pool_port))
        self.assertEqual((config['LISTEN_ADDR_IPV4'], config['PORT']), (endpoint.bind, endpoint.port))
        self.assertEqual(config['REPLAY_CHECK_LEN'], 65536)
        for name in ('USE_MIDDLE_PROXY', 'PREFER_IPV6', 'FAST_MODE', 'IGNORE_TIME_SKEW', 'MASK'):
            self.assertIs(config[name], False)
        self.assertIsNone(config['LISTEN_ADDR_IPV6'])
        self.assertIsNone(config['METRICS_PORT'])
        self.assertEqual(config['LISTEN_UNIX_SOCK'], '')
        self.assertEqual(config['CLIENT_IPS_LEN'], 0)

    def test_unit_has_resource_bounds_no_capabilities_no_peer_or_secret_journal(self):
        unit = installer.unit_text()
        for expected in ('User=vpn-mtproto-dd\n', 'Group=vpn-mtproto-dd\n',
                         'StandardOutput=null\n', 'StandardError=null\n',
                         'MemoryMax=128M\n', 'CPUQuota=50%\n', 'TasksMax=48\n',
                         'CapabilityBoundingSet=\n', 'AmbientCapabilities=\n',
                         'ProtectSystem=strict\n', 'NoNewPrivileges=true\n'):
            self.assertIn(expected, unit)
        self.assertNotIn('Requires=', unit)
        self.assertNotIn('BindsTo=', unit)
        self.assertNotIn('VPN_MTPROTO_SECRET', unit)
        self.assertNotIn('pip', unit)

    def test_private_ee_input_derives_same_key_and_rejects_symlink_or_weak_file(self):
        key, secret = ee_secret()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'secret.json'
            path.write_text(json.dumps({'secret': secret, 'other_metadata': 'ignored'}))
            path.chmod(0o600)
            self.assertEqual(installer.read_secrets(path), key)
            alias = path.with_name('alias')
            alias.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_secrets(alias)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'private regular'):
                installer.read_secrets(path)
            path.chmod(0o600)
            for invalid in ('dd' + key, secret + '\n', 'invalid', (b'\xee' + bytes(16) + b'a').hex()):
                path.write_text(json.dumps({'secret': invalid}))
                with self.assertRaises(RuntimeError):
                    installer.read_secrets(path)

    def test_pinned_assets_unpack_without_extractall_and_changed_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, wheel = fixture_assets(root)
            with patch.object(installer, 'ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest()), \
                    patch.object(installer, 'SOCKS_WHEEL_SHA256', hashlib.sha256(wheel.read_bytes()).hexdigest()):
                files = installer.read_assets(archive, wheel)
                self.assertIn(installer.SOURCE / 'mtprotoproxy.py', files)
                self.assertIn(installer.SOCKS / 'socks.py', files)
                self.assertIn(installer.MANIFEST, files)
                archive.write_bytes(archive.read_bytes() + b'changed')
                with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                    installer.read_assets(archive, wheel)

    def test_archive_traversal_and_links_are_refused_even_with_a_matching_hash(self):
        for name, symlink in (('../escape.py', False),
                              ('mtprotoproxy-' + installer.SOURCE_COMMIT + '/link', True)):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                member = tarfile.TarInfo(name)
                if symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                archive, wheel = fixture_assets(Path(temporary), member)
                with patch.object(installer, 'ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest()), \
                        patch.object(installer, 'SOCKS_WHEEL_SHA256', hashlib.sha256(wheel.read_bytes()).hexdigest()):
                    with self.assertRaises(RuntimeError):
                        installer.read_assets(archive, wheel)

    def test_failed_dependency_check_leaks_no_stderr_and_has_no_mutations(self):
        failure = type('Result', (), {'returncode': 1, 'stdout': b'', 'stderr': b'private traceback'})()
        with patch.object(installer.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(RuntimeError, '^MTProto DD installation command failed: python$'):
                installer.command('python', '-c', 'private code')
        key, _ = ee_secret()
        with patch.object(installer, 'endpoint_settings', return_value=settings()), \
                patch.object(installer, 'read_secrets', return_value=key), \
                patch.object(installer, 'read_assets', return_value={}), \
                patch.object(installer, 'check_dependency', side_effect=RuntimeError('missing crypto')), \
                patch.object(installer, 'command') as command, \
                patch.object(installer.os, 'chown') as chown:
            with self.assertRaisesRegex(RuntimeError, 'missing crypto'):
                installer.install(Path('archive'), Path('wheel'), Path('secret'))
            command.assert_not_called()
            chown.assert_not_called()

    def test_exclusive_private_write_has_exact_mode_under_umask(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(installer.os, 'fchown'):
            path = Path(temporary) / 'config.py'
            previous = os.umask(0o077)
            try:
                installer.write_new(path, b'private', 0o640, 123)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
                with self.assertRaises(FileExistsError):
                    installer.write_new(path, b'replacement', 0o640, 123)
                self.assertEqual(path.read_bytes(), b'private')
            finally:
                os.umask(previous)

    def test_identical_install_is_read_only_and_changed_key_is_refused(self):
        key, _ = ee_secret()
        endpoint = settings()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, config_directory = root / 'opt', root / 'etc'
            vendor = runtime / 'vendor'
            paths = {'RUNTIME': runtime, 'VENDOR': vendor, 'SOURCE': vendor / 'source',
                     'SOCKS': vendor / 'pysocks', 'CONFIG_DIRECTORY': config_directory,
                     'CONFIG': config_directory / 'config.py', 'MANIFEST': runtime / 'source-manifest.json',
                     'UNIT_PATH': root / 'vpn-mtproto-dd.service'}
            for name, path in paths.items():
                stack.enter_context(patch.object(installer, name, path))
            assets = {paths['SOURCE'] / 'mtprotoproxy.py': b'fixture',
                      paths['SOCKS'] / 'socks.py': b'fixture', paths['MANIFEST']: b'{}\n'}
            files = assets | {paths['CONFIG']: installer.config_text(key, endpoint).encode(),
                              paths['UNIT_PATH']: installer.unit_text().encode()}
            directories = installer.directories_for(files)
            for directory in directories:
                directory.mkdir(mode=0o750)
            for path, body in files.items():
                path.write_bytes(body)
                path.chmod(0o644 if path == paths['UNIT_PATH'] else 0o640)
            real_lstat = Path.lstat

            def root_owned(path):
                fields = list(real_lstat(path))
                fields[4], fields[5] = 0, 0 if path == paths['UNIT_PATH'] else 123
                return os.stat_result(fields)

            stack.enter_context(patch.object(Path, 'lstat', root_owned))
            stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=endpoint))
            secret_reader = stack.enter_context(patch.object(installer, 'read_secrets', return_value=key))
            stack.enter_context(patch.object(installer, 'read_assets', return_value=assets))
            stack.enter_context(patch.object(installer, 'check_dependency'))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
            listener = stack.enter_context(patch.object(installer, 'verify_listener'))

            def result(*args):
                return str(paths['UNIT_PATH']).encode() if '--property=FragmentPath' in args else b''

            command = stack.enter_context(patch.object(installer, 'command', side_effect=result))
            self.assertTrue(installer.install(root / 'archive', root / 'wheel', root / 'secret')['already_installed'])
            self.assertTrue(all(call.args[:2] in (('systemctl', 'show'), ('systemctl', 'is-active'))
                                for call in command.call_args_list))
            listener.assert_called_once_with(endpoint)
            command.reset_mock()
            secret_reader.return_value = secrets.token_hex(16)
            with self.assertRaisesRegex(RuntimeError, 'refusing to overwrite'):
                installer.install(root / 'archive', root / 'wheel', root / 'secret')
            command.assert_not_called()
            self.assertEqual(paths['CONFIG'].read_bytes(), files[paths['CONFIG']])
            (runtime / 'unexpected').write_text('preserve')
            with self.assertRaises(RuntimeError):
                installer.verify_files(files, directories, 123)
            self.assertEqual((runtime / 'unexpected').read_text(), 'preserve')

    def test_failed_new_start_removes_only_its_files_and_stops_only_its_unit(self):
        key, _ = ee_secret()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, config_directory = root / 'opt', root / 'etc'
            vendor = runtime / 'vendor'
            unrelated = root / 'existing-vpn'
            unrelated.write_bytes(b'unchanged')
            paths = {'RUNTIME': runtime, 'VENDOR': vendor, 'SOURCE': vendor / 'source',
                     'SOCKS': vendor / 'pysocks', 'CONFIG_DIRECTORY': config_directory,
                     'CONFIG': config_directory / 'config.py', 'MANIFEST': runtime / 'source-manifest.json',
                     'UNIT_PATH': root / 'vpn-mtproto-dd.service'}
            for name, path in paths.items():
                stack.enter_context(patch.object(installer, name, path))
            stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=settings()))
            stack.enter_context(patch.object(installer, 'read_secrets', return_value=key))
            stack.enter_context(patch.object(installer, 'read_assets', return_value={paths['SOURCE'] / 'mtprotoproxy.py': b'fixture'}))
            stack.enter_context(patch.object(installer, 'check_dependency'))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
            stack.enter_context(patch.object(installer, 'pool_available'))
            stack.enter_context(patch.object(installer.socket, 'socket'))
            stack.enter_context(patch.object(installer.os, 'chown'))
            stack.enter_context(patch.object(installer.os, 'fchown'))
            stack.enter_context(patch.object(installer, 'verify_listener', side_effect=RuntimeError('not ready')))
            def result(*args):
                if '--property=LoadState' in args:
                    return b'not-found'
                return str(paths['UNIT_PATH']).encode() if '--property=FragmentPath' in args else b''

            command = stack.enter_context(patch.object(installer, 'command', side_effect=result))
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                installer.install(root / 'archive', root / 'wheel', root / 'secret')
            self.assertFalse(runtime.exists())
            self.assertFalse(config_directory.exists())
            self.assertFalse(paths['UNIT_PATH'].exists())
            self.assertEqual(unrelated.read_bytes(), b'unchanged')
            service_commands = [call.args for call in command.call_args_list
                                if call.args[:2] in (('systemctl', 'enable'), ('systemctl', 'disable'))]
            self.assertEqual(service_commands, [('systemctl', 'enable', '--now', installer.UNIT),
                                                ('systemctl', 'disable', '--now', installer.UNIT)])


if __name__ == '__main__':
    unittest.main()
