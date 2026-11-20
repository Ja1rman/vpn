from contextlib import nullcontext
import copy
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import enable_telegram_local as installer
REAL_COMPILE = installer.compile_candidate
REAL_API_SNAPSHOT = installer.api_snapshot


class TelegramLocalTransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / 'runtime.json'
        self.backups = self.root / 'backups'
        self.runtime = {
            'inbounds': [
                {'tag': 'api', 'protocol': 'tunnel', 'port': port('VPN_XUI_API_PORT')},
                {'tag': 'authenticated-vless', 'protocol': 'vless', 'port': port('VPN_VLESS_AUTH_PORT'),
                 'settings': {'decryption': 'none', 'clients': [{'id': str(uuid4())}]}},
            ],
            'outbounds': [{'tag': 'api', 'protocol': 'freedom'},
                          {'tag': 'blocked', 'protocol': 'blackhole'},
                          {'tag': 'foreign', 'protocol': 'socks',
                           'settings': {'address': env('VPN_LOOPBACK_IP'),
                                        'port': port('VPN_BALANCER_SOCKS_PORT')}}],
            'routing': {'domainStrategy': 'AsIs', 'rules': copy.deepcopy(installer.routes.LEADING_RULES) + [
                {'type': 'field', 'inboundTag': ['authenticated-vless'], 'outboundTag': 'foreign'}]},
        }
        self.before = installer.core.json_bytes(self.runtime)
        self.config.write_bytes(self.before)
        self.config.chmod(0o600)
        self.template = self.before
        self.process = [1, 'unchanged-start']
        self.live = {'outbounds': {'api': 'original-api', 'blocked': 'original-blocked',
                                   'foreign': 'original-foreign'},
                     'inbounds': 'same-users-and-listeners', 'rules': 'original-rules'}
        self.live_before = copy.deepcopy(self.live)
        self.added = {tag: 'compiled-' + tag for tag in installer.routes.TAGS}
        self.events = []
        self.fail_runtime = False
        self.partial_ado = False
        patches = [
            patch.object(installer.core, 'CONFIG', self.config),
            patch.object(installer.core, 'BACKUPS', self.backups),
            patch.object(installer.core, 'runtime_identity', side_effect=lambda: self.process),
            patch.object(installer.core, 'read_template', side_effect=lambda: self.template),
            patch.object(installer.core, 'write_template', side_effect=self.write_template),
            patch.object(installer.core, 'write_runtime', side_effect=self.write_runtime),
            patch.object(installer.core, 'pin_live', side_effect=self.pin),
            patch.object(installer.core, 'command', return_value=b''),
            patch.object(installer.core, 'api', side_effect=self.api),
            patch.object(installer, 'api_snapshot', side_effect=lambda server=None: copy.deepcopy(self.live)),
            patch.object(installer, 'compile_candidate', return_value=(self.added, 'candidate-rules')),
            patch.object(installer, 'start_watchdog', side_effect=self.watchdog_ready),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        real_lstat = Path.lstat
        def root_owned(path):
            fields = list(real_lstat(path))
            fields[4] = fields[5] = 0
            return os.stat_result(fields)
        patcher = patch.object(Path, 'lstat', root_owned)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_template(self, old, new):
        self.assertEqual(self.template, old)
        self.template = new

    def write_runtime(self, old, new):
        self.assertEqual(self.config.read_bytes(), old)
        if self.fail_runtime:
            self.fail_runtime = False
            raise RuntimeError('fixture runtime persistence failure')
        self.config.write_bytes(new)

    def pin(self, config):
        has_own = set(installer.routes.TAGS) <= {x['tag'] for x in config['outbounds']}
        self.assertEqual(self.live['rules'], 'candidate-rules' if has_own else self.live_before['rules'])
        return set(self.live['outbounds'])

    def watchdog_ready(self, folder):
        self.events.append('watchdog-ready')
        installer.write_private(folder / 'watchdog-ready', b'{}')

    def api(self, action, *args):
        self.events.append(action)
        if action == 'ado':
            self.assertIn('watchdog-ready', self.events)
            tags = [item['tag'] for item in json.loads(Path(args[0]).read_bytes())['outbounds']]
            self.assertTrue(tags)
            self.assertTrue(all(tag not in self.live['outbounds'] for tag in tags))
            if self.partial_ado:
                self.partial_ado = False
                self.live['outbounds'][tags[0]] = self.added[tags[0]]
                raise RuntimeError('fixture partial handler failure')
            self.live['outbounds'].update({tag: self.added[tag] for tag in tags})
        elif action == 'adrules':
            self.live['rules'] = self.live_before['rules'] if Path(args[0]).name == 'routing-before.json' else 'candidate-rules'
        elif action == 'rmo':
            self.assertIn(args[0], installer.routes.TAGS)
            self.live['outbounds'].pop(args[0])
        else:
            self.fail('Unexpected API mutation')
        return b'{}'

    def arm(self):
        result = installer.apply()
        self.assertTrue(result['armed'])
        return Path(result['backup'])

    def test_apply_is_armed_not_committed_and_watchdog_bundle_survives_staging_cleanup(self):
        folder = self.arm()
        self.assertFalse((folder / 'committed').exists())
        self.assertTrue((folder / 'armed').exists())
        for name in ['enable_telegram_local.py', 'enable_failover_variant.py',
                     'telegram_local_routes.py', 'vpn_env.py', 'vpn.env.json']:
            self.assertTrue((folder / name).is_file())
            self.assertEqual((folder / name).stat().st_mode & 0o777, 0o600)
        current = json.loads(self.config.read_bytes())
        self.assertEqual(current['inbounds'], self.runtime['inbounds'])
        self.assertEqual(current['routing']['rules'][:3], self.runtime['routing']['rules'][:3])
        self.assertEqual(self.events[:3], ['watchdog-ready', 'ado', 'adrules'])

    def test_commit_requires_all_three_native_proofs_and_retains_only_booleans(self):
        folder = self.arm()
        for proof in [{}, {'native_mtp': True}, {'native_mtp': True, 'native_socks': 'true'},
                      {'native_mtp': False, 'native_socks': True, 'native_dd': True},
                      {'native_mtp': True, 'native_socks': True},
                      {'native_mtp': True, 'native_socks': True, 'native_dd': 'true'}]:
            with self.assertRaisesRegex(RuntimeError, 'external native'):
                installer.commit(folder, proof)
            self.assertFalse((folder / 'committed').exists())
        report = installer.commit(folder, {'native_mtp': True, 'native_socks': True, 'native_dd': True,
                                           'private_caller_detail': secrets.token_urlsafe(24)})
        self.assertTrue(report['committed'])
        self.assertEqual(json.loads((folder / 'external-proof.json').read_text()),
                         {'native_mtp': True, 'native_socks': True, 'native_dd': True})
        self.assertEqual(installer.rollback(folder), {'committed': True})

    def test_missing_external_proof_watchdog_restores_state_without_removing_old_handlers(self):
        folder = self.arm()
        baseline = json.loads((folder / 'baseline.json').read_text())
        baseline['deadline'] = time.time()-1
        (folder / 'baseline.json').write_bytes(installer.core.json_bytes(baseline))
        (folder / 'watchdog-ready').unlink()
        with patch.object(installer, 'locked', side_effect=nullcontext):
            installer.watchdog(folder)
        self.assertEqual(self.config.read_bytes(), self.before)
        self.assertEqual(self.template, self.before)
        self.assertEqual(self.live, self.live_before)
        self.assertTrue((folder / 'rolled-back').exists())

    def test_partial_handler_or_persistence_failure_rolls_back_all_owned_changes(self):
        for phase in ['partial_ado', 'fail_runtime']:
            with self.subTest(phase=phase):
                setattr(self, phase, True)
                with self.assertRaisesRegex(RuntimeError, 'fixture'):
                    installer.apply()
                self.assertEqual(self.config.read_bytes(), self.before)
                self.assertEqual(self.template, self.before)
                self.assertEqual(self.live, self.live_before)

    def test_concurrent_live_handler_change_refuses_rollback_before_any_mutation(self):
        folder = self.arm()
        self.live['outbounds']['foreign'] = 'owner-changed-existing-handler'
        events = list(self.events)
        with self.assertRaisesRegex(RuntimeError, 'Concurrent'):
            installer.rollback(folder)
        self.assertEqual(self.events, events)
        self.assertIn('foreign', self.live['outbounds'])

    def test_reapply_reports_existing_pending_transaction_without_new_route_changes(self):
        folder = self.arm()
        events = list(self.events)
        result = installer.apply()
        self.assertTrue(result['already_configured'])
        self.assertTrue(result['armed'])
        self.assertEqual(result['backup'], str(folder.resolve()))
        self.assertEqual(self.events, events)

    def test_compiler_cannot_inherit_production_listener_or_traffic_initiating_apps(self):
        original = copy.deepcopy(self.runtime)
        original.update(metrics={'listen': env('VPN_LOOPBACK_IP') + ':' + str(port('VPN_TEST_CANARY_PORT'))},
                        observatory={'probeUrl': 'https://example.org/'}, reverse={'portals': []})
        before = copy.deepcopy(original)
        result = installer.compiler_config(original, Path('/private-compiler/api.sock'))
        self.assertEqual(original, before)
        self.assertEqual(set(result), {'inbounds', 'log', 'outbounds', 'routing', 'api'})
        self.assertEqual(result['inbounds'], [])
        self.assertEqual(result['routing'], original['routing'])
        self.assertEqual(result['outbounds'], original['outbounds'])
        self.assertEqual(result['api']['listen'], '/private-compiler/api.sock')

    def test_failed_compiler_retains_private_diagnostic_after_temporary_directory_cleanup(self):
        class Exited:
            def poll(self):return 1
        def failed(*args, **kwargs):
            kwargs['stdout'].write(b'Failed to start: address already in use\n')
            return Exited()
        with patch.object(installer.subprocess, 'Popen', side_effect=failed):
            with self.assertRaisesRegex(RuntimeError, 'diagnostic log'):
                REAL_COMPILE(self.runtime)
        logs = list(self.backups.glob('telegram-compile-*/xray.log'))
        self.assertEqual(len(logs), 1)
        self.assertIn(b'address already in use', logs[0].read_bytes())
        self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)

    def test_partial_preflight_directory_does_not_mask_the_real_pending_transaction(self):
        folder = self.arm()
        partial = self.backups / (installer.PREFIX + 'incomplete-preflight')
        partial.mkdir(mode=0o700)
        for name in ('runtime-after.json', 'template-after.json'):
            installer.write_private(partial / name, (folder / name).read_bytes())
        self.assertEqual(installer.matching_pending(self.config.read_bytes(), self.template), folder.resolve())

    def prepare_legacy_two(self):
        self.assertEqual(len(installer.routes.TAGS), 3)
        self.legacy_tags = installer.routes.TAGS[:2]
        self.dd_tag = installer.routes.TAGS[2]
        auth_tags = installer.routes.eligible_inbound_tags(self.runtime)
        self.runtime['routing']['rules'][3:3] = installer.routes.expected_rules(auth_tags)[:2]
        self.runtime['outbounds'].extend(installer.routes.expected_outbounds()[:2])
        self.before = installer.core.json_bytes(self.runtime)
        self.config.write_bytes(self.before)
        self.template = self.before
        self.live['outbounds'].update({tag: self.added[tag] for tag in self.legacy_tags})
        self.live['rules'] = 'legacy-two-rules'
        self.live_before = copy.deepcopy(self.live)

    def test_legacy_two_to_three_sends_only_missing_dd_and_rollback_retains_old_handlers(self):
        self.prepare_legacy_two()
        old_handlers = copy.deepcopy(self.runtime['outbounds'])
        old_rules = copy.deepcopy(self.runtime['routing']['rules'])
        folder = self.arm()
        baseline = json.loads((folder / 'baseline.json').read_text())
        self.assertEqual(baseline['added'], {self.dd_tag: self.added[self.dd_tag]})
        payload = json.loads((folder / 'outbounds.json').read_text())
        self.assertEqual([item['tag'] for item in payload['outbounds']], [self.dd_tag])
        current = json.loads(self.config.read_bytes())
        self.assertEqual(current['outbounds'][:-1], old_handlers)
        self.assertEqual(current['routing']['rules'][3:5], old_rules[3:5])
        removed = []
        original_api = self.api
        def tracked(action, *args):
            if action == 'rmo':removed.append(args[0])
            return original_api(action, *args)
        with patch.object(installer.core, 'api', side_effect=tracked):
            installer.rollback(folder)
        self.assertEqual(removed, [self.dd_tag])
        self.assertEqual(self.live, self.live_before)
        self.assertEqual(self.config.read_bytes(), self.before)
        self.assertEqual(self.template, self.before)

    def test_legacy_two_must_match_compiled_live_settings_before_dd_addition(self):
        self.prepare_legacy_two()
        self.live['outbounds'][self.legacy_tags[0]] = 'owner-edited-existing-mtp-handler'
        with self.assertRaisesRegex(RuntimeError, 'existing local Telegram handler differs'):
            installer.apply()
        self.assertEqual(self.events, [])
        self.assertEqual(self.config.read_bytes(), self.before)
        self.assertEqual(self.template, self.before)

    def test_failed_dd_persistence_does_not_remove_preexisting_two_handlers(self):
        self.prepare_legacy_two()
        self.fail_runtime = True
        removed = []
        original_api = self.api
        def tracked(action, *args):
            if action == 'rmo':removed.append(args[0])
            return original_api(action, *args)
        with patch.object(installer.core, 'api', side_effect=tracked):
            with self.assertRaisesRegex(RuntimeError, 'fixture runtime'):
                installer.apply()
        self.assertEqual(removed, [self.dd_tag])
        self.assertEqual(self.live, self.live_before)
        self.assertEqual(self.config.read_bytes(), self.before)


class CanonicalApiSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.users = [{'email': 'fixture-a', 'account': {'id': str(uuid4()), 'flow': ''}},
                      {'email': 'fixture-b', 'account': {'id': str(uuid4()), 'flow': ''}}]
        self.data = {
            'lsi': {'inbounds': [
                {'tag': 'vpn-input', 'receiverSettings': {'portList': port('VPN_VLESS_AUTH_PORT')},
                 'proxySettings': {'users': copy.deepcopy(self.users)}},
                {'tag': 'api', 'receiverSettings': {'portList': port('VPN_XUI_API_PORT')}, 'proxySettings': {}},
            ]},
            'lso': {'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'},
                                 {'tag': 'foreign', 'protocol': 'socks'}]},
            'lsrules': {'rules': [{'tag': 'blocked', 'ruleTag': 'private'},
                                  {'tag': 'foreign', 'ruleTag': 'normal'}]},
        }

    def snapshot(self):
        with patch.object(installer.core, 'api', side_effect=lambda command: json.dumps(self.data[command]).encode()):
            return REAL_API_SNAPSHOT()

    def test_inbound_order_is_irrelevant_but_credential_changes_are_not(self):
        original = self.snapshot()
        self.data['lsi']['inbounds'].reverse()
        self.data['lso']['outbounds'].reverse()
        self.assertEqual(self.snapshot(), original)
        users = next(item for item in self.data['lsi']['inbounds'] if item['tag'] == 'vpn-input')['proxySettings']['users']
        users[0]['account']['id'] = str(uuid4())
        self.assertNotEqual(self.snapshot()['inbounds'], original['inbounds'])

    def test_receiver_changes_and_routing_rule_order_remain_strict(self):
        original = self.snapshot()
        self.data['lsrules']['rules'].reverse()
        self.assertNotEqual(self.snapshot()['rules'], original['rules'])
        self.data['lsi']['inbounds'][0]['receiverSettings']['portList'] = port('VPN_TEST_CANARY_PORT')
        self.assertNotEqual(self.snapshot()['inbounds'], original['inbounds'])

    def test_duplicate_membership_is_not_deduplicated_or_adopted(self):
        original = self.snapshot()
        self.data['lsi']['inbounds'][0]['proxySettings']['users'].append(copy.deepcopy(self.users[0]))
        self.assertNotEqual(self.snapshot()['inbounds'], original['inbounds'])
        self.data['lsi']['inbounds'].append(copy.deepcopy(self.data['lsi']['inbounds'][0]))
        with self.assertRaisesRegex(RuntimeError, 'duplicate inbound'):
            self.snapshot()


if __name__ == '__main__':
    unittest.main()
