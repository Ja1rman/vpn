"""Offline checks for the laptop wrapper's guarded native Telegram proof."""
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import deploy_telegram_local as deployment
import verify_telegram_proxy_clients as proof


class FakeController:
    def __init__(self, root, result, events):
        self.ROOT = root
        self.result = result
        self.events = events
        self.stage = None
        self.apply_error = None
        self.commit_packets = []

    def inventory(self):
        return {'entry': {'name': 'entry-fixture'}}

    def upload(self, name, folder, extras=()):
        self.stage = '/opt/vpn-infra/staging/' + name + '/' + folder.name
        self.events.append('upload')
        self.extras = tuple(extras)
        return self.stage

    def remote(self, name, command, data=None, capture=False):
        if name != 'entry-fixture':
            raise AssertionError('Unexpected deployment target')
        words = shlex.split(command)
        if 'rm' in words:
            if self.stage not in words or '--' not in words:
                raise AssertionError('Cleanup must address only the created stage')
            self.events.append('cleanup')
            return subprocess.CompletedProcess(words, 0, stdout=b'')
        if 'apply' in words:
            self.events.append('apply')
            if self.apply_error is not None:
                raise self.apply_error
            value = self.result
        elif 'commit' in words:
            self.events.append('commit')
            self.commit_packets.append(json.loads(data))
            value = {'committed': True, 'backup': self.result['backup']}
        elif 'rollback' in words:
            self.events.append('rollback')
            value = {'rolled_back': True, 'backup': self.result['backup']}
        else:
            raise AssertionError('Unexpected remote action')
        return subprocess.CompletedProcess(words, 0, stdout=json.dumps(value).encode())


class TelegramLaptopDeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / '.local').mkdir(mode=0o700)
        self.options = proof.Options(
            sing_box=self.root / 'sing-box', gotd=self.root / 'telegram-probe',
            subscriptions=self.root / 'subscription.json',
            mtproto_access=self.root / 'mtproto.json', socks_access=self.root / 'socks.json',
            report=self.root / 'report.json', dd_access=self.root / 'dd.json',
        )
        for executable in (self.options.sing_box, self.options.gotd):
            executable.write_bytes(b'private fixture only\n')
            executable.chmod(0o700)
        credentials = {
            self.options.subscriptions: {'sub_id': 'fixture_subscription'},
            self.options.mtproto_access: {'server': env('VPN_ENTRY_ADDRESS'),
                'port': port('VPN_MTPROTO_PUBLIC_PORT'),
                'secret': 'ee' + secrets.token_hex(16) + 'example.invalid'.encode().hex()},
            self.options.socks_access: {'server': env('VPN_ENTRY_ADDRESS'),
                'port': port('VPN_TELEGRAM_SOCKS_PORT'),
                'username': 'fixture-user', 'password': secrets.token_urlsafe(24)},
            self.options.dd_access: {'server': env('VPN_ENTRY_ADDRESS'),
                'port': port('VPN_MTPROTO_DD_PORT'), 'secret': 'dd' + secrets.token_hex(16)},
        }
        for path, value in credentials.items():
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        self.events = []
        self.backup = '/var/backups/vpn-infra/telegram-local-20990101T000000000000Z'
        self.controller = FakeController(self.root, {'armed': True, 'backup': self.backup}, self.events)
        self.prepared = {'sub_id': 'fixture_subscription', 'profile': {'fixture': True}}
        self.report = {'native_mtp': True, 'native_socks': True, 'native_dd': True,
                       'temporary_clients_stopped': True,
                       'private_caller_detail': secrets.token_urlsafe(24)}
        patches = (
            patch.object(deployment, 'build_probe', side_effect=self.build),
            patch.object(deployment.proof, 'prepare', side_effect=self.prepare),
            patch.object(deployment.proof, 'verify', side_effect=self.verify),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def build(self, output):
        self.events.append('build')
        return self.options.gotd

    def prepare(self, options):
        self.events.append('prepare')
        return self.prepared

    def verify(self, options, prepared=None):
        self.events.append('verify')
        if prepared != self.prepared:
            raise AssertionError('The prepared actual profile must be used')
        return self.report

    def test_success_commits_only_safe_native_booleans_then_cleans_stage(self):
        result = deployment.deploy(self.options, controller=self.controller)
        self.assertTrue(result['committed'])
        self.assertLess(self.events.index('build'), self.events.index('apply'))
        self.assertLess(self.events.index('prepare'), self.events.index('apply'))
        self.assertEqual(self.events[-3:], ['verify', 'commit', 'cleanup'])
        self.assertNotIn('rollback', self.events)
        self.assertEqual(len(self.controller.commit_packets), 1)
        packet = self.controller.commit_packets[0]
        self.assertIs(packet['native_mtp'], True)
        self.assertIs(packet['native_socks'], True)
        self.assertIs(packet['native_dd'], True)
        self.assertLessEqual(set(packet), {'native_mtp', 'native_socks', 'native_dd', 'transaction'})
        self.assertNotIn('private_caller_detail', packet)

    def test_failed_or_crashed_native_proof_rolls_back_before_cleanup(self):
        for crashed in (False, True):
            with self.subTest(crashed=crashed):
                self.events.clear()
                self.report = {'native_mtp': True, 'native_socks': False, 'native_dd': True,
                               'temporary_clients_stopped': True}
                if crashed:
                    action = patch.object(deployment.proof, 'verify', side_effect=RuntimeError('fixture client failure'))
                else:
                    action = patch.object(deployment.proof, 'verify', side_effect=self.verify)
                with action, self.assertRaises((RuntimeError, ValueError, subprocess.SubprocessError)):
                    deployment.deploy(self.options, controller=self.controller)
                self.assertEqual(self.events[-2:], ['rollback', 'cleanup'])
                self.assertNotIn('commit', self.events)

    def test_failed_or_missing_dd_proof_cannot_commit_the_other_two_successes(self):
        for missing, value in ((True, None), (False, False), (False, 'true')):
            with self.subTest(missing=missing, value=value):
                self.events.clear()
                self.report = {'native_mtp': True, 'native_socks': True,
                               'temporary_clients_stopped': True}
                if not missing:
                    self.report['native_dd'] = value
                with self.assertRaises(RuntimeError):
                    deployment.deploy(self.options, controller=self.controller)
                self.assertEqual(self.events[-2:], ['rollback', 'cleanup'])
                self.assertNotIn('commit', self.events)

    def test_deployment_without_dd_input_fails_before_any_remote_apply(self):
        with self.assertRaisesRegex(RuntimeError, 'DD|dd'):
            deployment.deploy(replace(self.options, dd_access=None), controller=self.controller)
        self.assertNotIn('upload', self.events)
        self.assertNotIn('apply', self.events)

    def test_existing_committed_state_has_optional_proof_without_commit_or_reset(self):
        self.controller.result = {'already_configured': True, 'armed': False, 'backup': None}
        for verify_existing in (False, True):
            with self.subTest(verify_existing=verify_existing):
                self.events.clear()
                deployment.deploy(self.options, verify_existing=verify_existing, controller=self.controller)
                self.assertEqual('verify' in self.events, verify_existing)
                self.assertNotIn('commit', self.events)
                self.assertNotIn('rollback', self.events)
                self.assertEqual(self.events[-1], 'cleanup')

    def test_apply_error_still_cleans_only_its_stage(self):
        self.controller.apply_error = subprocess.CalledProcessError(1, 'fixture apply')
        with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
            deployment.deploy(self.options, controller=self.controller)
        self.assertEqual(self.events[-1], 'cleanup')
        self.assertNotIn('verify', self.events)
        self.assertNotIn('commit', self.events)


class TelegramNativeProofTests(unittest.TestCase):
    def options(self, root):
        return proof.Options(root / 'sing-box', root / 'telegram-probe', root / 'subscription.json',
                             root / 'mtproto.json', root / 'socks.json', root / 'report.json')

    def profile(self):
        return {'type': 'vless', 'tag': 'VPN Auto', 'server': env('VPN_ENTRY_ADDRESS'),
                'server_port': port('VPN_AUTO_TLS_PUBLIC_PORT'), 'uuid': str(uuid4()),
                'packet_encoding': 'xudp', 'multiplex': {'enabled': False},
                'tls': {'enabled': True, 'server_name': env('VPN_ENTRY_ADDRESS'), 'insecure': False,
                        'utls': {'enabled': True, 'fingerprint': 'chrome'}}}

    def test_dd_client_uses_its_private_access_and_mtproto_over_the_same_auto_hop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = replace(self.options(root), dd_access=root / 'dd.json')
            hop = root / 'local-auto-socks.json'
            command = proof.client_command(options, 'dd', hop)
            self.assertEqual(command[command.index('--mode') + 1], 'mtproto')
            self.assertEqual(command[command.index('--access') + 1], str(options.dd_access.resolve()))
            self.assertNotIn(str(options.socks_access.resolve()), command)
            self.assertEqual(command[command.index('--via-socks') + 1], str(hop))
            with self.assertRaisesRegex(RuntimeError, 'DD'):
                proof.client_command(replace(options, dd_access=None), 'dd', hop)

    def test_prepare_checks_dd_endpoint_before_fetching_the_actual_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = replace(self.options(root), dd_access=root / 'dd.json')
            for executable in (options.sing_box, options.gotd):
                executable.write_bytes(b'fixture executable placeholder\n')
                executable.chmod(0o700)
            values = {
                options.subscriptions: {'sub_id': 'fixture_subscription'},
                options.mtproto_access: {'server': env('VPN_ENTRY_ADDRESS'),
                    'port': port('VPN_MTPROTO_PUBLIC_PORT'), 'secret': secrets.token_hex(16)},
                options.socks_access: {'server': env('VPN_ENTRY_ADDRESS'),
                    'port': port('VPN_TELEGRAM_SOCKS_PORT'),
                    'username': 'fixture-user', 'password': secrets.token_urlsafe(24)},
                options.dd_access: {'server': env('VPN_ENTRY_ADDRESS'),
                    'port': port('VPN_MTPROTO_DD_PORT'), 'secret': 'dd' + secrets.token_hex(16)},
            }
            for path, value in values.items():
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            profile = self.profile()
            with patch.object(proof, 'fetch_profile', return_value=profile) as fetch:
                self.assertEqual(proof.prepare(options), {'sub_id': 'fixture_subscription', 'profile': profile})
                fetch.assert_called_once_with('fixture_subscription')
            values[options.dd_access]['port'] = port('VPN_TEST_UNEXPECTED_PORT')
            options.dd_access.write_text(json.dumps(values[options.dd_access]))
            with patch.object(proof, 'fetch_profile') as fetch:
                with self.assertRaisesRegex(RuntimeError, 'does not match'):
                    proof.prepare(options)
                fetch.assert_not_called()

    def test_actual_profile_uses_nekobox_agent_and_refuses_weakened_tls_or_mux(self):
        profile = self.profile()
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda _name, default=None: default
        response.read.return_value = json.dumps({'outbounds': [profile]}).encode()
        with patch.object(proof.http.client, 'HTTPSConnection', return_value=connection):
            self.assertEqual(proof.fetch_profile('fixture_subscription'), profile)
        arguments, keywords = connection.request.call_args
        self.assertEqual(arguments, ('GET', '/sub/fixture_subscription'))
        self.assertEqual(keywords['headers']['User-Agent'], proof.NEKOBOX_AGENT)
        connection.close.assert_called_once()
        variants = []
        for name in ('mux', 'tls', 'destination'):
            changed = deepcopy(profile)
            if name == 'mux':
                changed['multiplex']['enabled'] = True
            elif name == 'tls':
                changed['tls']['insecure'] = True
            else:
                changed['server'] = env('VPN_TEST_ADDRESS_D')
            variants.append(changed)
        with patch.object(proof.http.client, 'HTTPSConnection', return_value=connection):
            for changed in variants:
                response.read.return_value = json.dumps({'outbounds': [changed]}).encode()
                with self.assertRaisesRegex(RuntimeError, 'differs from verified'):
                    proof.fetch_profile('fixture_subscription')

    def test_native_report_never_echoes_arbitrary_child_content_or_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            options = self.options(Path(directory))
            hidden = secrets.token_urlsafe(24)
            child = {'status': 'passed', 'key_exchange': 'passed', 'rpc': 'help.getNearestDC',
                     'nested_via_auto': True, 'account_login': False, 'elapsed_ms': 321,
                     'private_detail': hidden, 'uuid': str(uuid4()), 'server': env('VPN_ENTRY_ADDRESS')}
            completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(child).encode())
            with patch.object(proof.subprocess, 'run', return_value=completed) as run:
                mode, passed, report = proof.native_client(options, 'mtproto', Path(directory) / 'local.json')
            self.assertEqual(mode, 'mtproto')
            self.assertTrue(passed)
            self.assertEqual(set(report), {'mode', 'status', 'key_exchange', 'anonymous_rpc', 'elapsed_ms'})
            self.assertNotIn(hidden, json.dumps(report))
            self.assertNotIn(hidden, json.dumps(run.call_args.args))
            completed.returncode = 1
            with patch.object(proof.subprocess, 'run', return_value=completed):
                self.assertFalse(proof.native_client(options, 'mtproto', Path(directory) / 'local.json')[1])

    def test_local_build_uses_readonly_pinned_module_and_private_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / '.local/bin/telegram-probe'
            result = subprocess.CompletedProcess([], 0, stdout=b'', stderr=b'')
            with patch.object(deployment, 'ROOT', root), \
                    patch.object(deployment.subprocess, 'run', return_value=result) as run:
                self.assertEqual(deployment.build_probe(output), output.resolve())
            arguments = run.call_args.args[0]
            keywords = run.call_args.kwargs
            self.assertEqual(arguments[:2], ['go', 'build'])
            self.assertIn('-mod=readonly', arguments)
            self.assertEqual(arguments[arguments.index('-o') + 1], str(output.resolve()))
            self.assertEqual(keywords['cwd'], root / 'tools/telegram-probe')
            for key in ('GOCACHE', 'GOMODCACHE'):
                self.assertTrue(Path(keywords['env'][key]).is_relative_to(root / '.local'))


if __name__ == '__main__':
    unittest.main()
