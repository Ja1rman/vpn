from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port
import install_telegram_forwarders as installer
import vpn_env


def endpoints():
    return {
        'auto': installer.Forwarder(installer.NAMES['auto'], env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'),
                                     port('VPN_TEST_POOL_PORT'), port('VPN_TEST_EXIT_A_PORT')),
        'socks': installer.Forwarder(installer.NAMES['socks'], env('VPN_BIND_IP'), env('VPN_LOOPBACK_IP'),
                                      port('VPN_TEST_API_PORT'), port('VPN_TEST_EXIT_B_PORT')),
    }


class ForwarderInstallationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.units = self.root / 'units'
        self.units.mkdir()
        self.backups = self.root / 'backups'
        self.configured = endpoints()
        self.stack.enter_context(patch.object(installer, 'UNIT_DIR', self.units))
        self.stack.enter_context(patch.object(installer, 'settings', return_value=self.configured))
        self.stack.enter_context(patch.object(installer, 'proxy_binary', return_value=Path('/os/socket-proxyd')))
        self.stack.enter_context(patch.object(installer.os, 'fchown'))
        real_lstat = Path.lstat
        def owned(path):
            value = list(real_lstat(path))
            value[4] = value[5] = 0
            return os.stat_result(value)
        self.stack.enter_context(patch.object(Path, 'lstat', owned))
        self.command = self.stack.enter_context(patch.object(installer, 'command', side_effect=self.respond))
        self.preflight = self.stack.enter_context(patch.object(installer, 'preflight', return_value=False))

    @staticmethod
    def respond(*args, **kwargs):
        if 'SubState' in args:
            return b'listening\n'
        if 'ActiveState' in args:
            return b'inactive\n'
        if 'LoadState' in args:
            return b'not-found\n'
        return b''

    def test_units_use_fixed_loopback_targets_with_unprivileged_socket_activation(self):
        for item in self.configured.values():
            files = installer.unit_texts(item, Path('/os/socket-proxyd'))
            socket_text = files[self.units / (item.name + '.socket')].decode()
            service_text = files[self.units / (item.name + '.service')].decode()
            self.assertIn(f'ListenStream={item.bind}:{item.public_port}\n', socket_text)
            self.assertIn('Accept=no\n', socket_text)
            self.assertIn(f' {item.loopback}:{item.backend_port}\n', service_text)
            self.assertIn('DynamicUser=yes\n', service_text)
            self.assertIn('CapabilityBoundingSet=\n', service_text)
            self.assertNotIn('Restart=', service_text)
        with self.assertRaisesRegex(RuntimeError, 'Unknown'):
            installer.unit_texts(installer.Forwarder('owner-unit', '', '', 0, 0), Path('/os/socket-proxyd'))

    def test_install_creates_only_new_units_and_records_exact_ownership(self):
        owner = self.units / 'owner-existing.service'
        owner.write_text('owner service remains running')
        before = owner.read_bytes()
        result = installer.install(backup_root=self.backups)
        self.assertEqual(set(result['installed']), set(installer.NAMES.values()))
        manifest = Path(result['backup'])
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
        records = json.loads(manifest.read_text())['created']
        self.assertEqual(len(records), 4)
        self.assertEqual(owner.read_bytes(), before)
        for row in records:
            self.assertEqual(installer.unit_record(self.units / row['name']), row)
        for call in self.command.call_args_list:
            if 'enable' in call.args:
                self.assertEqual(set(call.args[3:]), {name + '.socket' for name in installer.NAMES.values()})
            self.assertNotIn('restart', call.args)

    def test_existing_active_identical_units_have_no_mutating_actions(self):
        installer.install(backup_root=self.backups)
        snapshots = {p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in self.units.iterdir()}
        # Invoke the real preflight captured on the module before mocking it.
        self.preflight.side_effect = REAL_PREFLIGHT
        self.command.reset_mock()
        result = installer.install(backup_root=self.backups)
        self.assertEqual(result['installed'], [])
        self.assertEqual(set(result['already_active']), set(installer.NAMES.values()))
        self.assertEqual({p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                          for p in self.units.iterdir()}, snapshots)
        self.assertTrue(all(call.args[:2] == ('systemctl', 'show') for call in self.command.call_args_list))

    def test_single_component_does_not_resolve_unused_public_or_backend_ports(self):
        values = {'VPN_BIND_IP': env('VPN_BIND_IP'), 'VPN_LOOPBACK_IP': env('VPN_LOOPBACK_IP'),
                  'VPN_AUTO_TLS_PUBLIC_PORT': port('VPN_TEST_POOL_PORT'),
                  'VPN_AUTO_TLS_PORT': port('VPN_TEST_EXIT_A_PORT')}
        with patch.object(vpn_env, 'value', side_effect=lambda name: values[name]):
            configured = REAL_SETTINGS('auto')
        self.assertEqual(set(configured), {'auto'})
        self.assertEqual(configured['auto'].public_port, values['VPN_AUTO_TLS_PUBLIC_PORT'])
        self.assertEqual(configured['auto'].backend_port, values['VPN_AUTO_TLS_PORT'])

    def test_startup_failure_rolls_back_only_its_new_units(self):
        owner = self.units / 'owner-existing.service'
        owner.write_text('keep')
        def fail_start(*args, **kwargs):
            if 'enable' in args:
                raise RuntimeError('fixture activation failure')
            return self.respond(*args, **kwargs)
        self.command.side_effect = fail_start
        with self.assertRaisesRegex(RuntimeError, 'fixture activation'):
            installer.install(backup_root=self.backups)
        self.assertEqual(list(self.units.iterdir()), [owner])
        self.assertEqual(owner.read_text(), 'keep')
        stopped = [call for call in self.command.call_args_list if 'stop' in call.args]
        self.assertEqual(len(stopped), 1)
        self.assertTrue(all(name in {x + '.service' for x in installer.NAMES.values()} for name in stopped[0].args[2:]))

    def test_edited_unit_blocks_entire_manual_rollback(self):
        result = installer.install(backup_root=self.backups)
        first = self.units / (installer.NAMES['auto'] + '.socket')
        first.write_bytes(first.read_bytes() + b'# owner edit\n')
        before = {p: p.read_bytes() for p in self.units.iterdir()}
        self.command.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'edited or replaced'):
            installer.rollback(Path(result['backup']))
        self.command.assert_not_called()
        self.assertEqual({p: p.read_bytes() for p in self.units.iterdir()}, before)

    def test_partial_file_write_failure_does_not_target_an_uncreated_service(self):
        original = installer.write_new
        def fail_second(path, data, mode):
            if path.suffix == '.service':
                raise OSError('fixture disk failure')
            return original(path, data, mode)
        with patch.object(installer, 'write_new', side_effect=fail_second):
            with self.assertRaises(OSError):
                installer.install(backup_root=self.backups)
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertFalse(any('stop' in call.args for call in self.command.call_args_list))


REAL_PREFLIGHT = installer.preflight
REAL_SETTINGS = installer.settings


if __name__ == '__main__':
    unittest.main()
