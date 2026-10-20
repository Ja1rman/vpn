"""Safety checks for the additive listener and subscription publication."""
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import compatible_profiles
from compatible_vless import build_config


def encoded_dummy_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def inbound_pair(user_ids):
    clients = [{"id": uid, "flow": ""} for uid in user_ids]
    source = {
        "protocol": "vless", "port": 33172,
        "settings": {"clients": clients},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {"serverNames": ["yandex.ru"],
                                "privateKey": encoded_dummy_key(), "shortIds": ["abcdef12"]},
        },
    }
    forward = {
        "protocol": "vless", "port": 46738, "listen": "0.0.0.0",
        "settings": {"clients": clients},
        "streamSettings": {"network": "tcp", "security": "none"},
    }
    return source, forward


class CompatibleRoutingSafety(unittest.TestCase):
    def test_each_authenticated_user_keeps_its_uuid_and_main_authorization(self):
        first, second, missing_main, disabled_main, disabled_source, extra_main = [
            str(uuid.uuid4()) for _ in range(6)
        ]
        source, forward = inbound_pair([first, second, missing_main, disabled_main, disabled_source])
        forward["settings"]["clients"] = [
            {"id": uid, "flow": ""} for uid in [first, second, disabled_main, disabled_source, extra_main]
        ]
        config = build_config(
            source, {uid: "" for uid in [first, second, missing_main, disabled_main]},
            forward_inbound=forward, forward_allowed={uid: "" for uid in [first, second, disabled_source]},
        )
        users = config["inbounds"][0]["users"]
        self.assertEqual({user["uuid"] for user in users}, {first, second})
        outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
        routes = {tuple(rule["auth_user"]): rule["outbound"] for rule in config["route"]["rules"]
                  if "auth_user" in rule}
        self.assertEqual(len(routes), 2)
        self.assertEqual(len(outbounds), 2)
        for user in users:
            outbound = outbounds[routes[(user["name"],)]]
            self.assertEqual(outbound["type"], "vless")
            self.assertEqual(outbound["server"], "127.0.0.1")
            self.assertEqual(outbound["server_port"], 46738)
            self.assertEqual(outbound["uuid"], user["uuid"])
            self.assertEqual(outbound["packet_encoding"], "xudp")
        self.assertEqual(config["route"]["rules"][-1], {"action": "reject"})
        self.assertNotIn("final", config["route"])
        self.assertTrue(all(outbound["type"] not in {"direct", "socks", "freedom"}
                            for outbound in outbounds.values()))


class CompatibleSubscriptionSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="compatible-profiles-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "panel.db"
        self.config = self.root / "config.json"
        self.user_ids = [str(uuid.uuid4()) for _ in range(4)]
        source, forward = inbound_pair(self.user_ids)
        allowed = dict.fromkeys(self.user_ids, "")
        self.config.write_text(json.dumps(build_config(
            source, allowed, forward_inbound=forward, forward_allowed=allowed,
        )))
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executescript("""
                CREATE TABLE clients (
                    id INTEGER PRIMARY KEY, uuid TEXT, email TEXT,
                    enable INTEGER, expiry_time INTEGER
                );
                CREATE TABLE client_external_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER,
                    kind TEXT, value TEXT, remark TEXT, sort_index INTEGER,
                    created_at INTEGER, enable INTEGER DEFAULT 1,
                    expiry_time INTEGER DEFAULT 0, name_prefix TEXT,
                    last_fetch_at INTEGER DEFAULT 0, last_fetch_error TEXT
                );
            """)
            for index, uid in enumerate(self.user_ids, 1):
                db.execute("INSERT INTO clients VALUES(?,?,?,?,?)",
                           (index, uid, "fixture-" + str(index), index != 3, 1 if index == 4 else 0))
            for index in (1, 2):
                db.execute(
                    "INSERT INTO client_external_links "
                    "(client_id,kind,value,remark,sort_index,created_at,enable,expiry_time,"
                    "name_prefix,last_fetch_at,last_fetch_error) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (index, "link", "ss://dummy-" + str(index) + "#previous", "previous", 7,
                     123, 1, 0, "", 0, ""),
                )
        self.previous = self.rows()
        # No subprocesses, production config, network sockets or root are needed.
        self.key_mock = patch.object(compatible_profiles, "x25519_public_key", return_value=encoded_dummy_key())
        self.key_mock.start()
        self.addCleanup(self.key_mock.stop)

    def rows(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM client_external_links ORDER BY id")]

    def publish(self):
        return compatible_profiles.publish_profiles(
            self.database, self.config, "203.0.113.1", self.root / "backups", check_ready=False,
        )

    def test_publication_preserves_previous_links_and_is_idempotent(self):
        result = self.publish()
        self.assertEqual(result["inserted_profiles"], 2)
        self.assertEqual(result["inactive_clients_skipped"], 2)
        after = self.rows()
        self.assertEqual(after[:2], self.previous)
        self.assertEqual({row["client_id"] for row in after[2:]}, {1, 2})
        for row in after[2:]:
            self.assertEqual(row["kind"], "link")
            uri = urllib.parse.urlsplit(row["value"])
            self.assertEqual(uri.port, 33173)
            self.assertEqual(uri.username, self.user_ids[row["client_id"] - 1])
            self.assertEqual(urllib.parse.unquote(uri.fragment), row["remark"])
            self.assertEqual(urllib.parse.parse_qs(uri.query)["packetEncoding"], ["xudp"])
        backup = Path(result["backup"])
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(file.stat().st_mode & 0o777 == 0o600 for file in backup.iterdir()))
        repeated = self.publish()
        self.assertEqual(repeated["inserted_profiles"], 0)
        self.assertEqual(repeated["existing_profiles_skipped"], 2)
        self.assertIsNone(repeated["backup"])
        self.assertEqual(self.rows(), after)

    def test_rollback_is_atomic_and_refuses_an_edited_published_row(self):
        result = self.publish()
        backup = Path(result["backup"])
        saved = json.loads((backup / "inserted.json").read_text())["rows"]
        # Editing the second row must also prevent deletion of the first one.
        edited = saved[-1]
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE client_external_links SET remark=? WHERE id=?", ("owner-edited", edited["id"]))
        before_failed_rollback = self.rows()
        with self.assertRaisesRegex(RuntimeError, "was edited"):
            compatible_profiles.rollback_profiles(self.database, backup)
        self.assertEqual(self.rows(), before_failed_rollback)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE client_external_links SET remark=? WHERE id=?", (edited["remark"], edited["id"]))
        undone = compatible_profiles.rollback_profiles(self.database, backup)
        self.assertEqual(undone["deleted_profiles"], 2)
        self.assertEqual(self.rows(), self.previous)
        repeated = compatible_profiles.rollback_profiles(self.database, backup)
        self.assertEqual(repeated["deleted_profiles"], 0)
        self.assertEqual(repeated["already_absent"], 2)


if __name__ == "__main__":
    unittest.main()
