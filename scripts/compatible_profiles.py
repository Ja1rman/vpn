#!/usr/bin/env python3
"""Publish the compatible VLESS listener as additive x-ui subscription links.

Only client_external_links is modified. Existing VPN settings, client records,
tokens, and running processes are never changed. Run ``plan`` before ``publish``;
``rollback`` removes only unchanged rows inserted by the selected publication.
"""
import argparse
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import time
import urllib.parse
import uuid


SERVICE = "vpn-compatible-vless"
DEFAULT_CONFIG = Path("/etc/vpn-compatible-vless/config.json")
DEFAULT_DATABASE = Path("/etc/x-ui/x-ui.db")
DEFAULT_BACKUP_ROOT = Path("/var/backups/vpn-infra")
PROFILE_PREFIX = "mc-ubuntu-breeze-reef-android-"
REQUIRED_COLUMNS = {
    "id", "client_id", "kind", "value", "remark", "sort_index", "created_at",
    "enable", "expiry_time", "name_prefix", "last_fetch_at", "last_fetch_error",
}


def now_millis():
    return int(time.time() * 1000)


def private_json(path, value):
    """Create a new private recovery file; never replace an existing manifest."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def x25519_public_key(encoded_private_key):
    """Derive the public key using OpenSSL, with private material only on stdin."""
    try:
        raw = base64.b64decode(
            encoded_private_key + "=" * (-len(encoded_private_key) % 4),
            altchars=b"-_", validate=True,
        )
    except (ValueError, TypeError):
        raise RuntimeError("Invalid REALITY private key encoding") from None
    if len(raw) != 32:
        raise RuntimeError("Invalid REALITY private key length")
    # RFC 8410: PKCS#8 X25519 private key and SubjectPublicKeyInfo public key.
    private_der = bytes.fromhex("302e020100300506032b656e04220420") + raw
    result = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private_der, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    prefix = bytes.fromhex("302a300506032b656e032100")
    if result.returncode or len(result.stdout) != len(prefix) + 32 or not result.stdout.startswith(prefix):
        raise RuntimeError("OpenSSL could not derive the REALITY public key")
    return base64.urlsafe_b64encode(result.stdout[len(prefix):]).decode().rstrip("=")


def listener_profile(config_path):
    config = json.loads(config_path.read_text())
    inbounds = [item for item in config.get("inbounds", [])
                if item.get("type") == "vless" and item.get("tag") == "compatible-vless"]
    if len(inbounds) != 1:
        raise RuntimeError("Expected exactly one compatible VLESS inbound")
    inbound = inbounds[0]
    port = int(inbound["listen_port"])
    if not 1024 <= port <= 65535:
        raise RuntimeError("Invalid compatible listener TCP port")
    tls = inbound.get("tls", {})
    reality = tls.get("reality", {})
    if not tls.get("enabled") or not reality.get("enabled"):
        raise RuntimeError("Compatible listener must enable TLS and REALITY")
    if inbound.get("transport"):
        raise RuntimeError("Only the compatible raw TCP listener is supported")
    if tls.get("server_name") != "yandex.ru":
        raise RuntimeError("Unexpected compatible listener SNI")
    short_ids = reality.get("short_id", [])
    if not short_ids or any(not isinstance(item, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", item)
                            for item in short_ids):
        raise RuntimeError("Invalid compatible listener short IDs")
    users = {}
    for user in inbound.get("users", []):
        try:
            uid = str(uuid.UUID(user["uuid"]))
        except (ValueError, TypeError, AttributeError, KeyError):
            raise RuntimeError("Invalid compatible listener user ID") from None
        flow = user.get("flow", "")
        if flow not in ("", "xtls-rprx-vision"):
            raise RuntimeError("Unsupported compatible listener VLESS flow")
        if uid in users:
            raise RuntimeError("Duplicate compatible listener user ID")
        users[uid] = flow
    if not users:
        raise RuntimeError("Compatible listener has no authorized users")
    return {
        "port": port, "sni": "yandex.ru", "short_id": short_ids[0],
        "public_key": x25519_public_key(reality["private_key"]), "users": users,
    }


def address_for_uri(address):
    try:
        parsed = ipaddress.ip_address(address)
        return "[" + str(parsed) + "]" if parsed.version == 6 else str(parsed)
    except ValueError:
        if len(address) > 253 or not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", address):
            raise RuntimeError("Address must be an IP address or hostname without a port") from None
        return address


def share_link(address, profile, uid, email):
    name = PROFILE_PREFIX + email
    query = {
        "encryption": "none", "security": "reality", "type": "tcp",
        "sni": profile["sni"], "fp": "chrome", "pbk": profile["public_key"],
        "sid": profile["short_id"], "packetEncoding": "xudp",
    }
    if profile["users"][uid]:
        query["flow"] = profile["users"][uid]
    value = ("vless://" + uid + "@" + address_for_uri(address) + ":" + str(profile["port"])
             + "?" + urllib.parse.urlencode(query)
             + "#" + urllib.parse.quote(name, safe=""))
    return name, value


def connect_database(database, writable=False):
    mode = "rw" if writable else "ro"
    db = sqlite3.connect(database.resolve().as_uri() + "?mode=" + mode,
                         uri=True, timeout=15, isolation_level=None)
    db.row_factory = sqlite3.Row
    columns = {row["name"] for row in db.execute("PRAGMA table_info(client_external_links)")}
    if not REQUIRED_COLUMNS.issubset(columns):
        db.close()
        raise RuntimeError("Unsupported x-ui external-link table schema")
    client_columns = {row["name"] for row in db.execute("PRAGMA table_info(clients)")}
    if not {"id", "uuid", "email", "enable", "expiry_time"}.issubset(client_columns):
        db.close()
        raise RuntimeError("Unsupported normalized x-ui client schema")
    return db


def publication_plan(db, address, profile):
    """Build a plan against the current DB, preserving all existing link rows."""
    now = now_millis()
    clients = {}
    inactive = 0
    for row in db.execute("SELECT id,uuid,email,enable,expiry_time FROM clients"):
        try:
            uid = str(uuid.UUID(row["uuid"]))
        except (ValueError, TypeError, AttributeError):
            continue
        if uid not in profile["users"]:
            continue
        if not row["enable"] or (int(row["expiry_time"] or 0) > 0 and int(row["expiry_time"]) <= now):
            inactive += 1
            continue
        if uid in clients:
            raise RuntimeError("An authorized UUID belongs to multiple active client records")
        clients[uid] = dict(row)
    if not clients:
        raise RuntimeError("No active panel client matches the compatible listener")
    additions = []
    skipped = 0
    for uid, client in clients.items():
        if not client["email"]:
            raise RuntimeError("An active client has no profile name")
        name, value = share_link(address, profile, uid, client["email"])
        rows = [dict(row) for row in db.execute(
            "SELECT * FROM client_external_links WHERE client_id=?", (client["id"],))]
        if any(row["remark"] == name and (row["kind"] != "link" or row["value"] != value)
               for row in rows):
            raise RuntimeError("An existing compatible profile name has a different URI; refusing to overwrite")
        identical = [row for row in rows if row["kind"] == "link" and row["value"] == value]
        if identical:
            if any(row["enable"] is None or bool(row["enable"]) for row in identical):
                if any((row["enable"] is None or bool(row["enable"])) and
                       (int(row["expiry_time"] or 0) <= 0 or int(row["expiry_time"]) > now)
                       for row in identical):
                    skipped += 1
                    continue
            raise RuntimeError("An identical compatible profile is disabled or expired; refusing to change it")
        additions.append({
            "client_id": client["id"], "kind": "link", "value": value, "remark": name,
            "enable": 1, "expiry_time": 0, "name_prefix": "", "last_fetch_at": 0,
            "last_fetch_error": "", "sort_index": max([int(row["sort_index"] or 0) for row in rows] + [-1]) + 1,
            "created_at": now,
        })
    return additions, {"eligible_clients": len(clients), "inactive_clients_skipped": inactive,
                       "existing_profiles_skipped": skipped, "profiles_to_add": len(additions)}


def require_listener_ready(port):
    status = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if status.returncode:
        raise RuntimeError("The compatible VLESS service is not active")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
    except OSError:
        raise RuntimeError("The compatible VLESS TCP listener is not reachable") from None


def database_identity(database):
    identity = database.stat()
    return {"database": str(database.resolve()), "device": identity.st_dev, "inode": identity.st_ino}


def publish_profiles(database, config_path, address, backup_root, check_ready=True):
    profile = listener_profile(config_path)
    address_for_uri(address)
    if check_ready:
        require_listener_ready(profile["port"])
    db = connect_database(database, writable=True)
    backup = None
    try:
        db.execute("BEGIN IMMEDIATE")
        additions, report = publication_plan(db, address, profile)
        if not additions:
            db.execute("COMMIT")
            return {**report, "inserted_profiles": 0, "backup": None}
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = backup_root / ("compatible-profiles-" + stamp)
        backup.mkdir(mode=0o700)
        identity = database_identity(database)
        before = [dict(row) for row in db.execute("SELECT * FROM client_external_links ORDER BY id")]
        private_json(backup / "before.json", {**identity, "rows": before})
        inserted = []
        for values in additions:
            columns = list(values)
            sql = ("INSERT INTO client_external_links (" + ",".join(columns)
                   + ") VALUES (" + ",".join("?" for _ in columns) + ")")
            cursor = db.execute(sql, [values[column] for column in columns])
            row = db.execute("SELECT * FROM client_external_links WHERE id=?", (cursor.lastrowid,)).fetchone()
            inserted.append(dict(row))
        # Recovery material is durable before the transaction is committed.
        private_json(backup / "inserted.json", {**identity, "rows": inserted})
        db.execute("COMMIT")
        return {**report, "inserted_profiles": len(inserted), "backup": str(backup)}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def rollback_profiles(database, backup):
    if backup.is_symlink() or not backup.is_dir():
        raise RuntimeError("Rollback backup must be a real directory")
    manifest = backup / "inserted.json"
    if manifest.is_symlink():
        raise RuntimeError("Rollback manifest must not be a symlink")
    saved = json.loads(manifest.read_text())
    identity = database_identity(database)
    if any(saved.get(key) != value for key, value in identity.items()):
        raise RuntimeError("Rollback backup belongs to a different database file")
    if not isinstance(saved.get("rows"), list) or not saved["rows"]:
        raise RuntimeError("Rollback manifest contains no inserted profiles")
    ids = [row.get("id") for row in saved["rows"]]
    if any(not isinstance(row_id, int) for row_id in ids) or len(set(ids)) != len(ids):
        raise RuntimeError("Rollback manifest has invalid or duplicated row IDs")
    db = connect_database(database, writable=True)
    try:
        db.execute("BEGIN IMMEDIATE")
        present = []
        missing = 0
        for old in saved["rows"]:
            current = db.execute("SELECT * FROM client_external_links WHERE id=?", (old["id"],)).fetchone()
            if current is None:
                missing += 1
                continue
            if dict(current) != old:
                raise RuntimeError("A published profile was edited; refusing the entire rollback")
            present.append(old["id"])
        for row_id in present:
            db.execute("DELETE FROM client_external_links WHERE id=?", (row_id,))
        db.execute("COMMIT")
        return {"deleted_profiles": len(present), "already_absent": missing, "backup": str(backup)}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "publish"):
        item = commands.add_parser(command)
        item.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
        item.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
        item.add_argument("--address", default="212.22.70.156")
        if command == "publish":
            item.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    item = commands.add_parser("rollback")
    item.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    item.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command in ("publish", "rollback") and os.geteuid() != 0:
            raise RuntimeError("Publication and rollback require root")
        if args.command == "plan":
            profile = listener_profile(args.config)
            db = connect_database(args.database)
            try:
                db.execute("BEGIN")
                _, report = publication_plan(db, args.address, profile)
                db.execute("ROLLBACK")
            finally:
                db.close()
        elif args.command == "publish":
            report = publish_profiles(args.database, args.config, args.address, args.backup_root)
        else:
            report = rollback_profiles(args.database, args.backup)
        print(json.dumps(report))
    except RuntimeError as exc:
        parser.exit(1, "compatible-profiles: " + str(exc) + "\n")
    except (ValueError, TypeError, OSError, KeyError, sqlite3.Error) as exc:
        # SQL, OpenSSL diagnostics, config values and UUIDs can contain secrets.
        parser.exit(1, "compatible-profiles: operation failed (" + type(exc).__name__ + ")\n")


if __name__ == "__main__":
    main()
