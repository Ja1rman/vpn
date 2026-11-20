"""Isolation, credentials, carrier framing and refusal contracts for WEB proxy."""
from contextlib import ExitStack, contextmanager
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import install_web_proxy as installer
import verify_web_proxy as verifier
import build_web_proxy as builder
import deploy_web_proxy as deployment


def settings():
    return installer.Endpoints('web.example', env('VPN_LOOPBACK_IP'), port('VPN_TEST_SNIFF_PORT'),
                               port('VPN_TEST_EXIT_C_PORT'), port('VPN_MTPROTO_DD_PORT'),
                               port('VPN_MONITORING_HTTP_PORT'))


def credentials():
    return {'secret': 'dd' + secrets.token_hex(16), 'base_path': secrets.token_hex(10),
            'token_key': secrets.token_hex(32)}


def executable():
    body = bytearray(32)
    body[:6], body[18:20] = b'\x7fELF\x02\x01', b'\x3e\x00'
    return bytes(body)


@contextmanager
def hostname_fixture():
    secret, old = credentials(), settings()
    desired = installer.replace(old, hostname='next.example')
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
        root = Path(temporary)
        runtime, etc = root / 'opt', root / 'etc'
        paths = {'RUNTIME': runtime, 'ROOT': etc, 'BINARY': runtime / 'tproxy-server',
                 'CONFIG': etc / 'config.json', 'PROFILES': etc / 'profiles.json',
                 'TOKEN': etc / 'token.key', 'MANIFEST': runtime / 'source-manifest.json',
                 'UNIT_PATH': root / 'unit.service', 'HOSTNAME_LOCK': root / 'hostname.lock',
                 'HOSTNAME_BACKUPS': root / 'backups'}
        for name, path in paths.items():
            stack.enter_context(patch.object(installer, name, path))
        runtime.mkdir(mode=0o755)
        etc.mkdir(mode=0o750)
        stack.enter_context(patch.object(installer, 'read_binary', return_value=executable()))
        digest = hashlib.sha256(executable()).hexdigest()
        files = installer.installation_files(Path('binary'), digest, secret, old)
        for path, body in files.items():
            path.write_bytes(body)
            path.chmod(installer.file_metadata(path, 123, 456)[2])
        original_lstat = Path.lstat

        def metadata(path):
            fields = list(original_lstat(path))
            if path in (runtime, etc):
                fields[4], fields[5] = 0, 456 if path == etc else 0
            elif path in files:
                fields[4], fields[5], _ = installer.file_metadata(path, 123, 456)
            return os.stat_result(fields)

        stack.enter_context(patch.object(Path, 'lstat', metadata))
        stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=desired))
        stack.enter_context(patch.object(installer, 'read_private', return_value=secret))
        stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 456)))
        stack.enter_context(patch.object(installer.os, 'fchown'))
        check_listener = stack.enter_context(patch.object(installer, 'verify_listener'))

        def successful_command(*arguments):
            return str(paths['UNIT_PATH']).encode() if '--property=FragmentPath' in arguments else b''

        command = stack.enter_context(patch.object(installer, 'command', side_effect=successful_command))
        yield SimpleNamespace(paths=paths, previous=old, desired=desired, credentials=secret,
                              digest=digest, files=files, command=command, listener=check_listener,
                              successful_command=successful_command)


class WebProxyTests(unittest.TestCase):
    def test_only_loopback_listeners_and_fixed_existing_dd_backend(self):
        secret, endpoint = credentials(), settings()
        config = json.loads(installer.config_text(secret, endpoint))
        profiles = json.loads(installer.profiles_text(secret, endpoint))
        self.assertEqual(config['listen'], f'{endpoint.loopback}:{endpoint.port}')
        self.assertEqual(config['admin_listen'], f'{endpoint.loopback}:{endpoint.admin_port}')
        self.assertEqual(config['public_hostname'], endpoint.hostname)
        self.assertIs(config['enable_pprof'], False)
        self.assertEqual(config['base_path'], secret['base_path'])
        self.assertEqual(profiles['profiles'], [{'name': 'vpn-auto', 'secret': secret['secret'],
                                               'backend': f'{endpoint.loopback}:{endpoint.backend_port}',
                                               'carrier_mode': 'https'}])
        self.assertNotIn(secret['secret'], json.dumps(config))
        self.assertLessEqual(config['limits']['max_pending_global'], 32 * 1024 * 1024)
        # A carrier batch may reserve thousands of uplink items concurrently.
        # Its queue still needs room for backend DATA and control messages.
        self.assertGreater(config['limits']['max_pending_items_per_session'],
                           4096 + config['limits']['max_streams_per_session'] * 8)

    def test_native_link_marker_and_capability_bind_hostname_and_path(self):
        secret, endpoint = credentials(), settings()
        access = installer.client_access(secret, endpoint)
        marked = access['secret']
        decoded = base64.urlsafe_b64decode(marked + '=' * (-len(marked) % 4))
        self.assertEqual(decoded, b'\x70' + bytes.fromhex(secret['secret']))
        self.assertEqual(access['server'], endpoint.hostname + '/' + secret['base_path'])
        self.assertTrue(access['link'].startswith('tg://webproxy?'))
        original = installer.bridge_capability(secret, endpoint)
        self.assertNotEqual(installer.bridge_capability(secret | {'base_path': 'other'}, endpoint), original)
        self.assertNotEqual(installer.bridge_capability(secret, installer.Endpoints(
            'other.example', endpoint.loopback, endpoint.port, endpoint.admin_port,
            endpoint.backend_port, endpoint.site_port)), original)

    def test_credentials_refuse_weak_permissions_links_traversal_and_plain_secret(self):
        secret = credentials()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'credentials.json'
            path.write_text(json.dumps(secret))
            path.chmod(0o600)
            self.assertEqual(installer.read_private(path), secret)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'owner-only'):
                installer.read_private(link)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'owner-only'):
                installer.read_private(path)
            path.chmod(0o600)
            for changed in ({'base_path': '../outside'}, {'base_path': ''}, {'base_path': 'a//b'},
                            {'base_path': 'a%2fb'}, {'token_key': ''}, {'secret': secret['secret'][2:]}):
                path.write_text(json.dumps(secret | changed))
                with self.assertRaises(RuntimeError):
                    installer.read_private(path)

    def test_hostname_and_standard_native_https_validation(self):
        installer.validate_hostname('web.example')
        for invalid in ('Web.example', 'single', 'web.example/', env('VPN_ENTRY_ADDRESS'), '-web.example'):
            with self.assertRaises(RuntimeError):
                installer.validate_hostname(invalid)
        endpoint = settings()
        overrides = {'VPN_WEB_PROXY_ADDRESS': endpoint.hostname, 'VPN_WEB_PROXY_PORT': str(endpoint.port),
                     'VPN_WEB_PROXY_ADMIN_PORT': str(endpoint.admin_port),
                     'VPN_MONITORING_HTTPS_PORT': str(http.client.HTTPS_PORT)}
        with patch.dict(os.environ, overrides):
            self.assertEqual(installer.endpoint_settings(), endpoint)
            with patch.dict(os.environ, {'VPN_WEB_PROXY_ADMIN_PORT': str(endpoint.port)}):
                with self.assertRaisesRegex(RuntimeError, 'distinct'):
                    installer.endpoint_settings()
        with patch.dict(os.environ, overrides | {'VPN_MONITORING_HTTPS_PORT': str(endpoint.port)}):
            with self.assertRaisesRegex(RuntimeError, 'standard HTTPS'):
                installer.endpoint_settings()

    def test_no_capabilities_no_sensitive_journal_and_existing_vpn_has_no_dependency_restart(self):
        unit = installer.unit_text()
        for expected in ('User=vpn-telegram-web\n', 'MemoryMax=128M\n', 'CPUQuota=50%\n',
                         'CapabilityBoundingSet=\n', 'AmbientCapabilities=\n', 'StandardOutput=null\n',
                         'StandardError=null\n', 'NoNewPrivileges=true\n', 'ProtectSystem=strict\n'):
            self.assertIn(expected, unit)
        self.assertNotIn('Requires=', unit)
        self.assertNotIn('BindsTo=', unit)
        self.assertNotIn('PartOf=', unit)
        self.assertNotIn('ExecReload=', unit)
        location = installer.nginx_location(credentials(), settings())
        self.assertIn('proxy_pass http://', location)
        self.assertIn('proxy_set_header Host $host;', location)
        self.assertIn('access_log off;', location)
        self.assertIn('proxy_buffering off;', location)
        self.assertNotIn('/grafana', location)
        self.assertNotIn('ssl_certificate', location)
        self.assertEqual(installer.file_metadata(installer.PROFILES, 123, 456), (123, 456, 0o600))
        self.assertEqual(installer.file_metadata(installer.TOKEN, 123, 456), (123, 456, 0o600))
        self.assertEqual(installer.file_metadata(installer.CONFIG, 123, 456), (0, 456, 0o640))

    def test_bounded_regular_binary_checks_sha_and_architecture(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'binary'
            path.write_bytes(executable())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(installer.read_binary(path, digest), executable())
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                installer.read_binary(path, '0' * 64)
            path.write_bytes(b'wrong executable')
            with self.assertRaisesRegex(RuntimeError, 'amd64'):
                installer.read_binary(path, hashlib.sha256(path.read_bytes()).hexdigest())
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'regular bounded'):
                installer.read_binary(link, digest)

    def test_exclusive_writes_preserve_prior_file_and_sanitize_failed_commands(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(installer.os, 'fchown'):
            path = Path(temporary) / 'config'
            installer.write_new(path, b'private', 0o640, 123)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            with self.assertRaises(FileExistsError):
                installer.write_new(path, b'replacement', 0o640, 123)
            self.assertEqual(path.read_bytes(), b'private')
        result = type('Result', (), {'returncode': 1, 'stdout': b'', 'stderr': b'private'})()
        with patch.object(installer.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, '^WEB relay installation command failed: check$'):
                installer.command('check', 'private')

    def test_missing_environment_refuses_before_mutation(self):
        with patch.object(installer, 'endpoint_settings', side_effect=ValueError('missing')), \
                patch.object(installer, 'command') as command, \
                patch.object(installer, 'write_new') as write:
            with self.assertRaises(ValueError):
                installer.install(Path('binary'), 'digest', Path('secret'))
            command.assert_not_called()
            write.assert_not_called()

    def test_carrier_frames_roundtrip_and_reject_truncation_and_bounds(self):
        batch = verifier.frame(0x01, 1) + verifier.frame(0x02, 1, b'opaque')
        self.assertEqual(verifier.frames(batch), [(0x01, 1, b''), (0x02, 1, b'opaque')])
        for invalid in (b'', b'\x01', batch[:-1]):
            with self.assertRaises(RuntimeError):
                verifier.frames(invalid)
        with self.assertRaises(RuntimeError):
            verifier.frame(0x02, 0x1000000)

    def test_changed_existing_installation_is_refused_without_service_commands(self):
        secret, endpoint = credentials(), settings()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, etc = root / 'opt', root / 'etc'
            paths = {'RUNTIME': runtime, 'ROOT': etc, 'BINARY': runtime / 'tproxy-server',
                     'CONFIG': etc / 'config.json', 'PROFILES': etc / 'profiles.json',
                     'TOKEN': etc / 'token.key', 'MANIFEST': runtime / 'source-manifest.json',
                     'UNIT_PATH': root / 'unit.service'}
            for name, path in paths.items():
                stack.enter_context(patch.object(installer, name, path))
            runtime.mkdir()
            stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=endpoint))
            stack.enter_context(patch.object(installer, 'read_private', return_value=secret))
            stack.enter_context(patch.object(installer, 'read_binary', return_value=executable()))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
            command = stack.enter_context(patch.object(installer, 'command'))
            with self.assertRaisesRegex(RuntimeError, 'Unexpected existing WEB relay directory'):
                installer.install(Path('binary'), 'digest', Path('secret'))
            command.assert_not_called()

    def test_new_start_failure_rolls_back_only_new_unit_and_keeps_files_if_stop_fails(self):
        for stop_fails in (False, True):
            with self.subTest(stop_fails=stop_fails), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                root = Path(temporary)
                runtime, etc = root / 'opt', root / 'etc'
                paths = {'RUNTIME': runtime, 'ROOT': etc, 'BINARY': runtime / 'tproxy-server',
                         'CONFIG': etc / 'config.json', 'PROFILES': etc / 'profiles.json',
                         'TOKEN': etc / 'token.key', 'MANIFEST': runtime / 'source-manifest.json',
                         'UNIT_PATH': root / 'unit.service'}
                for name, path in paths.items():
                    stack.enter_context(patch.object(installer, name, path))
                stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=settings()))
                stack.enter_context(patch.object(installer, 'read_private', return_value=credentials()))
                stack.enter_context(patch.object(installer, 'read_binary', return_value=executable()))
                stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 123)))
                stack.enter_context(patch.object(installer, 'verify_listener', side_effect=RuntimeError('not ready')))
                stack.enter_context(patch.object(installer.socket, 'create_connection', return_value=MagicMock()))
                stack.enter_context(patch.object(installer.os, 'chown'))
                stack.enter_context(patch.object(installer.os, 'fchown'))

                def result(*arguments):
                    if '--property=LoadState' in arguments:
                        return b'not-found\n'
                    if stop_fails and arguments[:3] == ('systemctl', 'disable', '--now'):
                        raise RuntimeError('stop failed')
                    return b''

                command = stack.enter_context(patch.object(installer, 'command', side_effect=result))
                with self.assertRaisesRegex(RuntimeError, 'preserved' if stop_fails else 'not ready'):
                    installer.install(Path('binary'), 'digest', Path('secret'))
                stop_commands = [call.args for call in command.call_args_list
                                 if call.args[:2] == ('systemctl', 'disable')]
                self.assertEqual(stop_commands, [('systemctl', 'disable', '--now', installer.UNIT)])
                self.assertEqual(runtime.exists(), stop_fails)
                self.assertEqual(etc.exists(), stop_fails)
                self.assertEqual(paths['UNIT_PATH'].exists(), stop_fails)

    def test_empty_carrier_poll_has_no_content_type_but_frames_do(self):
        endpoint = settings()
        secret = credentials()
        carrier = verifier.Carrier({'origin': f'http://{endpoint.loopback}:{endpoint.port}',
                                    'hostname': endpoint.hostname, **secret})
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status, response.read.return_value, response.getheaders.return_value = 204, b'', []
        with patch.object(verifier.http.client, 'HTTPConnection', return_value=connection):
            carrier.request('POST', 'api/v1/down', 'private', b'')
            headers = connection.request.call_args.kwargs['headers']
            self.assertNotIn('Content-Type', headers)
            carrier.request('POST', 'api/v1/up', 'private', verifier.frame(0x01, 1))
            headers = connection.request.call_args.kwargs['headers']
            self.assertEqual(headers['Content-Type'], 'application/octet-stream')

    def test_source_build_refuses_checksum_changes_and_unsafe_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source.tar.gz'
            for member_name, linked in (('../outside', False),
                                         ('tproxy-server-' + builder.SOURCE_COMMIT + '/link', True)):
                member = tarfile.TarInfo(member_name)
                with tarfile.open(path, 'w:gz') as archive:
                    if linked:
                        member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
                        archive.addfile(member)
                    else:
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b'x'))
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                with patch.object(builder, 'SOURCE_SHA256', digest):
                    with self.assertRaisesRegex(RuntimeError, 'Unsafe|Links'):
                        builder.source_files(path)
                with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                    builder.source_files(path)

    def test_prepare_preserves_credentials_and_refuses_environment_rotation(self):
        secret, endpoint = credentials(), settings()
        with tempfile.TemporaryDirectory() as temporary, patch.object(installer, 'endpoint_settings', return_value=endpoint):
            root = Path(temporary)
            private = root / '.local/web-proxy'
            private.mkdir(parents=True)
            (root / '.local/mtproto-dd').mkdir()
            access = root / '.local/mtproto-dd/access.json'
            access.write_text(json.dumps({'secret': secret['secret']}))
            access.chmod(0o600)
            binary = private / 'tproxy-server-linux-amd64'
            binary.write_bytes(executable())
            manifest = {'source_commit': installer.SOURCE_COMMIT, 'source_sha256': installer.SOURCE_SHA256,
                        'binary_sha256': hashlib.sha256(executable()).hexdigest()}
            (private / 'build.json').write_text(json.dumps(manifest))
            controller = SimpleNamespace(ROOT=root, port=lambda name: http.client.HTTPS_PORT)
            with patch.dict(os.environ, {'VPN_WEB_PROXY_CREDENTIALS_JSON': ''}):
                first = deployment.prepare(controller)
                stable = first['credentials'].read_bytes()
                second = deployment.prepare(controller)
                self.assertEqual(second['credentials'].read_bytes(), stable)
            self.assertEqual(json.loads(stable)['secret'], secret['secret'])
            self.assertEqual(verifier.read_private(private / 'proof-settings.json')['hostname'], endpoint.hostname)
            for name in ('credentials.json', 'proof-settings.json', 'access.json', 'access.md', 'nginx-location.conf'):
                self.assertEqual(stat.S_IMODE((private / name).stat().st_mode), 0o600)
            with patch.dict(os.environ, {'VPN_WEB_PROXY_CREDENTIALS_JSON': json.dumps(secret)}):
                with self.assertRaisesRegex(RuntimeError, 'implicit rotation'):
                    deployment.prepare(controller)
            self.assertEqual(first['credentials'].read_bytes(), stable)

    def test_deploy_failure_cleans_only_the_owned_entry_staging_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.local').mkdir()
            binary, credentials_file = root / 'binary', root / 'credentials'
            binary.write_bytes(executable())
            credentials_file.write_text(json.dumps(credentials()))
            prepared = {'binary': binary, 'credentials': credentials_file, 'binary_sha256': '0' * 64}
            controller = SimpleNamespace(ROOT=root, inventory=lambda: {'entry': {'name': 'entry'}})
            controller.upload = MagicMock(side_effect=lambda name, folder, extras:
                                           '/opt/vpn-infra/staging/' + name + '/' + folder.name)
            commands = []

            def remote(name, command, **kwargs):
                commands.append((name, command))
                if 'install_web_proxy.py' in command:
                    raise RuntimeError('new installation failed')

            controller.remote = remote
            with patch.object(deployment, 'prepare', return_value=prepared):
                with self.assertRaisesRegex(RuntimeError, 'new installation failed'):
                    deployment.deploy(controller)
            self.assertEqual(len(commands), 2)
            self.assertTrue(all(name == 'entry' for name, _ in commands))
            self.assertIn('sudo rm -rf -- /opt/vpn-infra/staging/entry/telegram-web-', commands[-1][1])
            self.assertNotIn('systemctl', ' '.join(command for _, command in commands))

    def test_identical_install_is_read_only_and_signing_key_drift_is_refused(self):
        secret, endpoint = credentials(), settings()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            runtime, etc = root / 'opt', root / 'etc'
            paths = {'RUNTIME': runtime, 'ROOT': etc, 'BINARY': runtime / 'tproxy-server',
                     'CONFIG': etc / 'config.json', 'PROFILES': etc / 'profiles.json',
                     'TOKEN': etc / 'token.key', 'MANIFEST': runtime / 'source-manifest.json',
                     'UNIT_PATH': root / 'unit.service'}
            for name, path in paths.items():
                stack.enter_context(patch.object(installer, name, path))
            runtime.mkdir(mode=0o755)
            etc.mkdir(mode=0o750)
            digest = hashlib.sha256(executable()).hexdigest()
            files = {paths['BINARY']: executable(), paths['CONFIG']: installer.config_text(secret, endpoint).encode(),
                     paths['PROFILES']: installer.profiles_text(secret, endpoint).encode(),
                     paths['TOKEN']: bytes.fromhex(secret['token_key']), paths['UNIT_PATH']: installer.unit_text().encode(),
                     paths['MANIFEST']: (json.dumps({'source_commit': installer.SOURCE_COMMIT,
                                                     'source_sha256': installer.SOURCE_SHA256,
                                                     'binary_sha256': digest}, sort_keys=True) + '\n').encode()}
            for path, body in files.items():
                path.write_bytes(body)
                path.chmod(installer.file_metadata(path, 123, 456)[2])
            original_lstat = Path.lstat

            def metadata(path):
                fields = list(original_lstat(path))
                if path in (runtime, etc):
                    fields[4], fields[5] = 0, 456 if path == etc else 0
                elif path in files:
                    fields[4], fields[5], _ = installer.file_metadata(path, 123, 456)
                return os.stat_result(fields)

            stack.enter_context(patch.object(Path, 'lstat', metadata))
            stack.enter_context(patch.object(installer, 'endpoint_settings', return_value=endpoint))
            secret_reader = stack.enter_context(patch.object(installer, 'read_private', return_value=secret))
            stack.enter_context(patch.object(installer, 'read_binary', return_value=executable()))
            stack.enter_context(patch.object(installer, 'check_account', return_value=(123, 456)))
            stack.enter_context(patch.object(installer, 'verify_listener'))
            command = stack.enter_context(patch.object(installer, 'command', side_effect=lambda *arguments:
                                                        str(paths['UNIT_PATH']).encode()
                                                        if '--property=FragmentPath' in arguments else b''))
            self.assertTrue(installer.install(Path('binary'), digest, Path('secret'))['already_installed'])
            self.assertEqual([call.args[:2] for call in command.call_args_list],
                             [('systemctl', 'show'), ('systemctl', 'is-active')])
            command.reset_mock()
            secret_reader.return_value = secret | {'token_key': secrets.token_hex(32)}
            with self.assertRaisesRegex(RuntimeError, 'refusing to overwrite'):
                installer.install(Path('binary'), digest, Path('secret'))
            command.assert_not_called()
            self.assertEqual(paths['TOKEN'].read_bytes(), files[paths['TOKEN']])

    def test_hostname_migration_changes_only_hostname_and_restarts_only_new_web_unit(self):
        with hostname_fixture() as fixture:
            unaffected = {path: (path.read_bytes(), path.stat().st_ino) for path in fixture.files
                          if path != fixture.paths['CONFIG']}
            result = installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                                 fixture.previous.hostname)
            self.assertTrue(result['retargeted'])
            self.assertFalse(result['vpn_services_restarted'])
            previous = json.loads(fixture.files[fixture.paths['CONFIG']])
            current = json.loads(fixture.paths['CONFIG'].read_text())
            self.assertEqual(current.pop('public_hostname'), fixture.desired.hostname)
            previous.pop('public_hostname')
            self.assertEqual(current, previous)
            self.assertTrue(all((path.read_bytes(), path.stat().st_ino) == original
                                for path, original in unaffected.items()))
            self.assertEqual([call.args for call in fixture.command.call_args_list
                              if call.args[:2] == ('systemctl', 'restart')],
                             [('systemctl', 'restart', installer.UNIT)])
            backup = Path(result['backup']) / 'config.json'
            self.assertEqual(backup.read_bytes(), fixture.files[fixture.paths['CONFIG']])
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            fixture.listener.assert_called_once_with(fixture.credentials, fixture.desired)
            fixture.command.reset_mock()
            self.assertTrue(installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                                        fixture.previous.hostname)['already_retargeted'])
            self.assertFalse(any(call.args[:2] == ('systemctl', 'restart')
                                 for call in fixture.command.call_args_list))

    def test_hostname_migration_refuses_other_config_drift_before_commands(self):
        with hostname_fixture() as fixture:
            config = json.loads(fixture.paths['CONFIG'].read_text())
            config['limits']['max_sessions_global'] += 1
            fixture.paths['CONFIG'].write_text(json.dumps(config))
            with self.assertRaisesRegex(RuntimeError, 'refusing to overwrite'):
                installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                             fixture.previous.hostname)
            fixture.command.assert_not_called()
            self.assertEqual(json.loads(fixture.paths['CONFIG'].read_text()), config)

    def test_hostname_migration_cas_preserves_a_concurrent_config_edit(self):
        with hostname_fixture() as fixture:
            concurrent = fixture.files[fixture.paths['CONFIG']] + b'\n'

            def command(*arguments):
                if arguments[0] == 'runuser':
                    fixture.paths['CONFIG'].write_bytes(concurrent)
                return fixture.successful_command(*arguments)

            fixture.command.side_effect = command
            with self.assertRaisesRegex(RuntimeError, 'changed concurrently'):
                installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                             fixture.previous.hostname)
            self.assertEqual(fixture.paths['CONFIG'].read_bytes(), concurrent)
            self.assertFalse(any(call.args[:2] == ('systemctl', 'restart')
                                 for call in fixture.command.call_args_list))
            self.assertEqual(set(fixture.paths['ROOT'].iterdir()),
                             {fixture.paths[key] for key in ('CONFIG', 'PROFILES', 'TOKEN')})

    def test_failed_hostname_health_check_restores_old_config_and_restarts_only_web(self):
        with hostname_fixture() as fixture:
            fixture.listener.side_effect = [RuntimeError('new bridge unavailable'), None]
            with self.assertRaisesRegex(RuntimeError, 'new bridge unavailable'):
                installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                             fixture.previous.hostname)
            self.assertEqual(fixture.paths['CONFIG'].read_bytes(), fixture.files[fixture.paths['CONFIG']])
            self.assertEqual([call.args for call in fixture.command.call_args_list
                              if call.args[:2] == ('systemctl', 'restart')],
                             [('systemctl', 'restart', installer.UNIT)] * 2)
            self.assertEqual(fixture.listener.call_args.args, (fixture.credentials, fixture.previous))
            self.assertTrue(all(path.read_bytes() == body for path, body in fixture.files.items()))

    def test_hostname_rollback_refuses_to_overwrite_post_restart_concurrent_change(self):
        with hostname_fixture() as fixture:
            concurrent = b'changed by another operator\n'

            def unavailable(*arguments):
                fixture.paths['CONFIG'].write_bytes(concurrent)
                raise RuntimeError('new bridge unavailable')

            fixture.listener.side_effect = unavailable
            with self.assertRaisesRegex(RuntimeError, 'backup retained'):
                installer.retarget_hostname(Path('binary'), fixture.digest, Path('secret'),
                                             fixture.previous.hostname)
            self.assertEqual(fixture.paths['CONFIG'].read_bytes(), concurrent)
            self.assertEqual(len([call for call in fixture.command.call_args_list
                                  if call.args[:2] == ('systemctl', 'restart')]), 1)

    def test_deploy_retarget_passes_explicit_previous_hostname_and_accepts_only_retarget_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.local').mkdir()
            binary, credential_file = root / 'binary', root / 'credentials'
            binary.write_bytes(executable())
            credential_file.write_text(json.dumps(credentials()))
            prepared = {'binary': binary, 'credentials': credential_file, 'binary_sha256': '0' * 64}
            controller = SimpleNamespace(ROOT=root, inventory=lambda: {'entry': {'name': 'entry'}})
            controller.upload = lambda name, folder, extras: '/opt/vpn-infra/staging/' + name + '/' + folder.name
            result = {'unit': installer.UNIT, 'retargeted': True}
            controller.remote = MagicMock(side_effect=lambda *args, **kwargs:
                                           SimpleNamespace(stdout=json.dumps(result).encode()))
            with patch.object(deployment, 'prepare', return_value=prepared):
                self.assertTrue(deployment.deploy(controller, previous_hostname='previous.example')['retargeted'])
            install_command = controller.remote.call_args_list[0].args[1]
            self.assertIn('retarget-hostname', install_command)
            self.assertIn('--previous-hostname previous.example', install_command)
            self.assertNotIn('systemctl', install_command)


if __name__ == '__main__':
    unittest.main()
