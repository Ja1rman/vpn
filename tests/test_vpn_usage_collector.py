from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from vpn_usage_collector import collect, read_mapping


class UsageCollectorTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.db, self.devices, self.output = (root / name for name in ('x-ui.db', 'devices.json', 'usage.prom'))
        with closing(sqlite3.connect(self.db)) as conn:
            conn.executescript('''
                CREATE TABLE clients(id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                    sub_id TEXT, uuid TEXT, password TEXT);
                CREATE TABLE client_traffics(id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                    inbound_id INTEGER, up INTEGER, down INTEGER);
                CREATE TABLE client_inbounds(client_id INTEGER, inbound_id INTEGER);
                CREATE TABLE client_hwids(sub_id TEXT, hwid_hash TEXT);
                INSERT INTO clients VALUES
                    (1, 'one@hidden.invalid', 'private-sub-one', 'private-uuid-one', 'private-pass-one'),
                    (2, 'two@hidden.invalid', 'private-sub-two', 'private-uuid-two', ''),
                    (3, 'three@hidden.invalid', 'private-sub-three', 'private-uuid-three', ''),
                    (4, 'four@hidden.invalid', 'private-sub-four', 'private-uuid-four', '');
                INSERT INTO client_traffics VALUES (10,'one@hidden.invalid',20,11,101),
                    (11,'two@hidden.invalid',20,22,202), (12,'three@hidden.invalid',30,0,0);
                INSERT INTO client_inbounds VALUES (1,20),(1,30),(2,20),(3,30);
                INSERT INTO client_hwids VALUES ('private-sub-one','hidden-hwid');
            ''')
            conn.commit()

    def put_mapping(self, data):
        self.devices.write_text(data if isinstance(data, str) else json.dumps(data))
        self.devices.chmod(0o600)

    def test_grouped_device_counters_do_not_multiply_traffic_or_expose_credentials(self):
        self.put_mapping({'1': {'subscription': 'family', 'device': 'phone'},
                          '2': {'subscription': 'family', 'device': 'laptop'}})
        collect(self.db, self.devices, self.output)
        data = self.output.read_text()
        for subscription, device, values in [('family', 'phone', (11, 101)),
                                             ('family', 'laptop', (22, 202)),
                                             ('sub-3', '', (0, 0))]:
            labels = f'subscription="{subscription}",device="{device}"'
            for direction, value in zip(('upload', 'download'), values):
                self.assertIn(f'vpn_usage_traffic_bytes_total{{{labels},direction="{direction}"}} {value}\n', data)
        self.assertEqual(data.count('\nvpn_usage_traffic_bytes_total{'), 6)
        self.assertIn('vpn_usage_identity_info{subscription="sub-4",device=""} 1', data)
        self.assertRegex(data, r'(?m)^vpn_usage_last_success_timestamp_seconds [1-9][0-9]*$')
        for secret in ('hidden.invalid', 'private-sub-', 'private-uuid-', 'private-pass-', 'hidden-hwid'):
            self.assertNotIn(secret, data)

    def test_invalid_mapping_leaves_previous_atomic_snapshot(self):
        collect(self.db, self.devices, self.output)
        snapshot = self.output.read_bytes()
        self.put_mapping({'1': {'subscription': 'family', 'device': 'phone'},
                          '2': {'subscription': 'family', 'device': 'phone'}})
        with self.assertRaises(ValueError):
            collect(self.db, self.devices, self.output)
        self.assertEqual(self.output.read_bytes(), snapshot)
        self.assertEqual(list(self.output.parent.glob('.usage.prom.*')), [])

    def test_mapping_cannot_smuggle_a_private_credential_or_default_group(self):
        self.put_mapping({'1': {'subscription': 'private-sub-one', 'device': ''}})
        with self.assertRaisesRegex(ValueError, 'matches a private'):
            collect(self.db, self.devices, self.output)
        self.put_mapping({'1': {'subscription': 'sub-2', 'device': 'phone'}})
        with self.assertRaisesRegex(ValueError, 'reserved'):
            read_mapping(self.devices)
        self.assertFalse(self.output.exists())

    def test_invalid_keys_duplicate_json_and_unsafe_labels_are_rejected(self):
        for value in ('{"1":{"subscription":"f","device":"d"},"1":{}}',
                      '{"01":{"subscription":"f","device":"d"}}',
                      '{"1":{"subscription":"f\\nforge","device":"d"}}'):
            with self.subTest(value=value):
                self.put_mapping(value)
                with self.assertRaises(ValueError):
                    read_mapping(self.devices)

    def test_missing_database_is_not_created(self):
        absent = self.db.with_name('missing.db')
        with self.assertRaises(FileNotFoundError):
            collect(absent, self.devices, self.output)
        self.assertFalse(absent.exists())
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
