from contextlib import closing
import ipaddress
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_environment import configure
configure()
from vpn_env import env, port as env_port, expand
import xray_subscription_hosts as hosts


class NativeSubscriptionHostsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database, self.backups = self.root / 'panel.db', self.root / 'backups'
        self.address = ipaddress.IPv4Address(env('VPN_TEST_ADDRESS_A'))
        with closing(sqlite3.connect(self.database)) as db:
            fields = hosts.desired_host(1, env_port('VPN_STANDARD_TLS_PORT'), self.address)
            declarations = [key + (' INTEGER' if isinstance(value, int) else ' TEXT')
                            for key, value in fields.items()]
            db.execute('CREATE TABLE hosts(id INTEGER PRIMARY KEY AUTOINCREMENT,group_id TEXT,' +
                       ','.join(declarations) + ',created_at INTEGER,updated_at INTEGER)')
            db.executescript('''
                CREATE TABLE inbounds(id INTEGER PRIMARY KEY,port INTEGER UNIQUE,
                    protocol TEXT,enable INTEGER,exclude_from_sub INTEGER,stream_settings TEXT);
                CREATE TABLE clients(id INTEGER PRIMARY KEY,uuid TEXT);
                CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER);
                CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,value TEXT);
                CREATE TABLE settings(key TEXT,value TEXT);
                INSERT INTO clients VALUES(1,'existing-private-credential');
                INSERT INTO client_inbounds VALUES(1,1);
                INSERT INTO client_external_links VALUES(1,'ss://existing-unchanged');
                INSERT INTO settings VALUES('unrelated','keep');
            ''')
            for index, port in enumerate(hosts.PORTS, 1):
                db.execute('INSERT INTO inbounds VALUES(?,?,?,?,?,?)',
                           (index, port, 'vless', 1, 0, json.dumps({'network': 'tcp', 'security': 'none'})))
            db.commit()
        self.protected_before = self.protected()

    def protected(self):
        with closing(sqlite3.connect(self.database)) as db:
            return {table: db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
                    for table in ('inbounds', 'clients', 'client_inbounds', 'client_external_links', 'settings')}

    def rows(self):
        with closing(hosts.connect(self.database)) as db:
            return [dict(row) for row in db.execute('SELECT * FROM hosts ORDER BY id')]

    def apply(self):
        with patch.object(hosts, 'verify_tls_listeners') as verify:
            result = hosts.apply(self.database, self.address, self.backups)
        verify.assert_called_once_with(self.address)
        return result

    def test_native_hosts_are_idempotent_and_do_not_copy_credentials_or_change_inbounds(self):
        with closing(hosts.connect(self.database)) as db:
            additions, report = hosts.publication_plan(db, self.address)
        self.assertEqual(report['native_tls_hosts_to_insert'], 4)
        self.assertNotIn('existing-private-credential', json.dumps(additions))
        first = self.apply()
        self.assertEqual(first['inserted'], 4)
        self.assertEqual([row['port'] for row in self.rows()], list(hosts.PORTS.values()))
        self.assertTrue(all(row['security'] == 'tls' and row['allow_insecure'] == 0 for row in self.rows()))
        self.assertEqual(self.protected(), self.protected_before)
        self.assertEqual(self.apply()['inserted'], 0)
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO clients VALUES(2,?)', ('new-private-credential',))
            db.execute('INSERT INTO client_inbounds VALUES(2,1)')
            db.commit()
        self.assertEqual(self.apply()['inserted'], 0)
        self.assertEqual(len(self.rows()), 4)
        backup = Path(first['backup'])
        self.assertEqual(hosts.rollback(self.database, backup)['deleted'], 4)
        self.assertEqual(hosts.rollback(self.database, backup)['already_absent'], 4)

    def test_existing_unrelated_host_is_not_changed_or_adopted(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute(expand('INSERT INTO hosts(inbound_id,port,security,remark) VALUES(1,${VPN_TEST_UNEXPECTED_PORT},?,?)'),
                       ('tls', 'owner-defined'))
            db.commit()
        before = self.rows()
        with self.assertRaisesRegex(RuntimeError, 'existing native host'):
            self.apply()
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.protected(), self.protected_before)

    def test_recovery_refuses_all_deletions_when_one_owned_host_was_edited(self):
        report = self.apply()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('UPDATE hosts SET remark=? WHERE id=(SELECT MIN(id) FROM hosts)', ('owner edit',))
            db.commit()
        before = self.rows()
        with self.assertRaisesRegex(RuntimeError, 'edited'):
            hosts.rollback(self.database, Path(report['backup']))
        self.assertEqual(self.rows(), before)

    def test_tls_verification_failure_prevents_any_database_change(self):
        with patch.object(hosts, 'verify_tls_listeners', side_effect=RuntimeError('not trusted')):
            with self.assertRaisesRegex(RuntimeError, 'not trusted'):
                hosts.apply(self.database, self.address, self.backups)
        self.assertEqual(self.rows(), [])
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.protected(), self.protected_before)

    def test_manifest_write_failure_rolls_back_new_hosts(self):
        original = hosts.private_json
        def fail_manifest(path, value):
            if path.name == 'inserted.json':
                raise OSError('fixture disk failure')
            original(path, value)
        with patch.object(hosts, 'private_json', side_effect=fail_manifest):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.protected(), self.protected_before)


if __name__ == '__main__':
    unittest.main()
