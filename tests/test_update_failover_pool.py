import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from failover_variant import build_pool
from update_failover_pool import append_plan, selector_guard
import update_failover_pool as updater


class FailoverPoolAppendTests(unittest.TestCase):
    def pool(self, names):
        sites, definitions = [], []
        addresses = {'primary': '1.1.1.1', 'backup': '8.8.8.8', 'next': '9.9.9.9'}
        for name in names:
            sites.append({'name': name, 'address': addresses[name], 'source': 'main', 'tag': name})
            definitions.append({'tag': name, 'protocol': 'vless', 'settings': {
                'address': addresses[name], 'port': 443,
                'id': '00000000-0000-4000-8000-000000000001', 'encryption': 'none',
            }, 'streamSettings': {'network': 'raw', 'security': 'tls'}})
        return build_pool({'egresses': sites, 'probe_urls': ['https://probe.invalid/health']},
                          {'outbounds': definitions}, {'outbounds': [], 'policy': {'system': {}},
                           'inbounds': [{'tag': 'pool-socks'}, {'tag': 'api'}]})[0]

    def test_append_adds_only_new_exit_and_bridge(self):
        old = self.pool(['primary', 'backup'])
        desired = self.pool(['primary', 'backup', 'next'])
        sites, additions = append_plan(old, desired)
        self.assertEqual([o['tag'] for o in sites], ['pool-site-next'])
        self.assertEqual([o['tag'] for o in additions], ['pool-site-next', 'failover-hop-2'])
        self.assertEqual(append_plan(old, copy.deepcopy(old)), ([], []))

    def test_reorder_replace_remove_or_listener_change_cannot_hot_update(self):
        old = self.pool(['primary', 'backup'])
        changed = self.pool(['primary', 'backup', 'next'])
        changed['outbounds'][1]['settings']['id'] = '00000000-0000-4000-8000-000000000002'
        different_policy = self.pool(['primary', 'backup', 'next'])
        different_policy['policy']['system']['statsOutboundUplink'] = True
        different_port = self.pool(['primary', 'backup', 'next'])
        different_port['inbounds'][0]['port'] += 1
        for candidate in (self.pool(['backup', 'primary', 'next']), self.pool(['primary', 'next']),
                          changed, different_policy, different_port):
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                append_plan(old, candidate)

    def test_retained_live_handler_cannot_expand_new_selector(self):
        old = self.pool(['primary', 'backup'])
        desired = self.pool(['primary', 'backup', 'next'])
        retained = {'pool-site-next-retired'}
        selector_guard(old, {o['tag'] for o in old['outbounds']} | retained)
        with self.assertRaisesRegex(RuntimeError, 'retained runtime outbound collides'):
            selector_guard(desired, {o['tag'] for o in desired['outbounds']} | retained)

    def test_only_nonempty_live_override_is_refused(self):
        pool = self.pool(['primary', 'backup'])
        handlers = {out['tag']: None for out in pool['outbounds']}
        listing = [b'  - Selecting Override:\n    1                 \n  - Selects:\n    1   pool-site-primary\n',
                   b'  - Selects:\n    1   pool-site-backup\n']
        with patch.object(updater, 'live_rules', return_value=updater.expected_rules(pool)):
            with patch.object(updater, 'api', side_effect=listing):
                updater.pin_live(pool, handlers)
            with patch.object(updater, 'api', return_value=listing[0].replace(b'1                 ',
                                                                            b'1   pool-site-backup')):
                with self.assertRaisesRegex(RuntimeError, 'has an override'):
                    updater.pin_live(pool, handlers)


if __name__ == '__main__':
    unittest.main()
