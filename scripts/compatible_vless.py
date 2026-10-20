#!/usr/bin/env python3
"""Add a compatible sing-box REALITY frontend; never change x-ui/Xray.

Each frontend UUID authenticates again to the existing local main VLESS listener,
which retains live authorization, traffic accounting, and routing to the pool.
Adding users to the frontend requires an explicit reviewed update; there is no
background synchronizer.
"""
import argparse
import base64
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid

VERSION = "1.14.3"
ARCHIVE_SHA256 = "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"
SERVICE = "vpn-compatible-vless"
RUNTIME = Path("/opt") / SERVICE
CONFIG_DIR = Path("/etc") / SERVICE
CONFIG = CONFIG_DIR / "config.json"
UNIT = Path("/etc/systemd/system") / (SERVICE + ".service")
UNIT_TEXT = """[Unit]
Description=Compatible VLESS REALITY frontend to the main Xray VPN entry
After=network-online.target vpn-balancer.service
Wants=network-online.target
[Service]
User=vpn-compatible-vless
Group=vpn-compatible-vless
WorkingDirectory=/opt/vpn-compatible-vless
ExecStart=/opt/vpn-compatible-vless/sing-box run -c /etc/vpn-compatible-vless/config.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
SystemCallArchitectures=native
MemoryMax=512M
LimitNOFILE=65536
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def run(*args):
    """Capture daemon diagnostics because configuration errors can contain secrets."""
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("Command failed: " + str(args[0]) + " " + str(args[1]))
    return result.stdout


def source_inbound(path, port, reality=True):
    config = json.loads(path.read_text())
    matches = [i for i in config["inbounds"]
               if i.get("protocol") == "vless" and i.get("port") == port]
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one source VLESS inbound")
    inbound = matches[0]
    stream = inbound["streamSettings"]
    if stream.get("network") not in ("tcp", "raw"):
        raise RuntimeError("Source must use TCP")
    if reality and stream.get("security") != "reality":
        raise RuntimeError("Source must use REALITY")
    if not reality and stream.get("security", "none") != "none":
        raise RuntimeError("Main forwarding inbound must use unencrypted local TCP")
    return inbound


def enabled_clients(database, port):
    """Read authorization from the panel DB without obtaining a panel API token."""
    now = int(time.time() * 1000)
    uri = database.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        inbound = db.execute(
            "SELECT * FROM inbounds WHERE port=? AND protocol='vless' AND enable=1", (port,)
        ).fetchall()
        if len(inbound) != 1:
            raise RuntimeError("Source inbound is missing, duplicated, or disabled in the panel")
        inbound = dict(inbound[0])
        if int(inbound.get("expiry_time", 0) or 0) > 0 and int(inbound["expiry_time"]) <= now:
            raise RuntimeError("Source inbound has expired")
        inbound_quota = int(inbound.get("total", 0) or 0)
        if inbound_quota > 0 and int(inbound.get("up", 0)) + int(inbound.get("down", 0)) >= inbound_quota:
            raise RuntimeError("Source inbound has exhausted its traffic quota")
        if "client_inbounds" in tables and "clients" in tables:
            # Current normalized 3x-ui database; no writes or API reloads.
            rows = db.execute(
                "SELECT c.*, ci.flow_override FROM clients c JOIN client_inbounds ci "
                "ON ci.client_id=c.id WHERE ci.inbound_id=?", (inbound["id"],)
            ).fetchall()
            clients = [dict(row) for row in rows]
        else:
            clients = json.loads(inbound["settings"]).get("clients", [])
        traffic = {}
        if "client_traffics" in tables:
            traffic = {r["email"]: dict(r) for r in db.execute(
                "SELECT * FROM client_traffics WHERE inbound_id=?", (inbound["id"],))}
        # Normalized client limits are shared across inbounds/nodes. Do not copy
        # an already exhausted client just because this one inbound used little.
        local_usage = {}
        if "client_traffics" in tables:
            local_usage = dict(db.execute(
                "SELECT email,SUM(up+down) FROM client_traffics GROUP BY email"))
        global_usage = {}
        if "client_global_traffics" in tables:
            global_usage = dict(db.execute(
                "SELECT email,SUM(up+down) FROM client_global_traffics GROUP BY email"))
        result = {}
        for client in clients:
            if not client.get("enable", True):
                continue
            expiry = int(client.get("expiry_time", client.get("expiryTime", 0)) or 0)
            if expiry > 0 and expiry <= now:
                continue
            stats = traffic.get(client.get("email", ""), {})
            if not stats.get("enable", True):
                continue
            quota = int(client.get("total_gb", client.get("totalGB", 0)) or 0)
            # Both classic totalGB and normalized total_gb store bytes in 3x-ui.
            email = client.get("email", "")
            used = max(local_usage.get(email, 0) or 0, global_usage.get(email, 0) or 0)
            if quota > 0 and used >= quota:
                continue
            uid = client.get("uuid", client.get("id"))
            flow = client.get("flow_override") or client.get("flow", "")
            result[str(uid)] = flow
        if not result:
            raise RuntimeError("No enabled, unexpired clients remain")
        return result


def build_config(inbound, allowed, port=33173, listen="0.0.0.0", *,
                 forward_inbound=None, forward_allowed=None):
    if not 1024 <= port <= 65535:
        raise RuntimeError("Use an unprivileged TCP port from 1024 to 65535")
    socket.inet_pton(socket.AF_INET, listen)
    if forward_inbound is None:
        raise RuntimeError("The existing main VLESS forwarding inbound is required")
    forward_stream = forward_inbound.get("streamSettings", {})
    if (forward_inbound.get("protocol") != "vless"
            or forward_stream.get("network") not in ("tcp", "raw")
            or forward_stream.get("security", "none") != "none"):
        raise RuntimeError("Main forwarding inbound must be plain TCP VLESS")
    forward_port = int(forward_inbound["port"])
    if not 1 <= forward_port <= 65535 or forward_port == port:
        raise RuntimeError("Invalid main forwarding port")
    if forward_inbound.get("listen", "0.0.0.0") not in ("", "0.0.0.0", "127.0.0.1", "::"):
        raise RuntimeError("Main forwarding inbound must accept loopback connections")
    forwarding = {str(uuid.UUID(c["id"])): c.get("flow", "")
                  for c in forward_inbound["settings"]["clients"]}
    reality = inbound["streamSettings"]["realitySettings"]
    if "yandex.ru" not in reality.get("serverNames", []):
        raise RuntimeError("The source REALITY inbound no longer permits yandex.ru")
    private = reality["privateKey"]
    if len(base64.urlsafe_b64decode(private + "=" * (-len(private) % 4))) != 32:
        raise RuntimeError("Invalid source REALITY private key")
    short_ids = reality["shortIds"]
    if not short_ids or any(not re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", s) for s in short_ids):
        raise RuntimeError("Invalid source REALITY short IDs")
    users = []
    outbounds = []
    rules = [{"ip_is_private": True, "action": "reject"}]
    seen = set()
    for client in inbound["settings"]["clients"]:
        uid = str(uuid.UUID(client["id"]))
        if (uid in seen or uid not in forwarding
                or (allowed is not None and uid not in allowed)
                or (forward_allowed is not None and uid not in forward_allowed)):
            continue
        seen.add(uid)
        flow = client.get("flow", "") if allowed is None else allowed[uid]
        if flow not in ("", "xtls-rprx-vision"):
            raise RuntimeError("A client uses an unsupported VLESS flow")
        forward_flow = forwarding[uid] if forward_allowed is None else forward_allowed[uid]
        if forward_flow:
            raise RuntimeError("Plain main VLESS forwarding requires empty client flow")
        # No email/UUID is logged as the user name.
        identity = hashlib.sha256(uid.encode()).hexdigest()[:12]
        name = "client-" + identity
        tag = "main-" + identity
        users.append({"name": name, "uuid": uid, "flow": flow})
        outbounds.append({"type": "vless", "tag": tag, "server": "127.0.0.1",
                          "server_port": forward_port, "uuid": uid, "packet_encoding": "xudp"})
        rules.append({"auth_user": [name], "action": "route", "outbound": tag})
    if not users:
        raise RuntimeError("No running source client matches enabled panel authorization")
    return {
        "log": {"level": "warn", "timestamp": True},
        # This resolver serves the camouflage handshake. Client destinations keep
        # their original domains and are forwarded to the main Xray listener.
        "dns": {"servers": [{"type": "local", "tag": "system"}]},
        "inbounds": [{
            "type": "vless", "tag": "compatible-vless", "listen": listen,
            "listen_port": port, "users": users,
            "tls": {"enabled": True, "server_name": "yandex.ru", "reality": {
                "enabled": True, "handshake": {"server": "yandex.ru", "server_port": 443},
                "private_key": private, "short_id": short_ids,
            }},
        }],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "system",
            # Unknown users cannot fall through to the first outbound.
            "rules": rules + [{"action": "reject"}],
        },
    }


def config_bytes(config):
    return (json.dumps(config, indent=2) + "\n").encode()


def render(args):
    inbound = source_inbound(args.source_config, args.source_port)
    forward = source_inbound(args.source_config, args.forward_port, reality=False)
    allowed = None if args.runtime_only else enabled_clients(args.database, args.source_port)
    forward_allowed = None if args.runtime_only else enabled_clients(args.database, args.forward_port)
    config = build_config(inbound, allowed, args.port, args.listen,
                          forward_inbound=forward, forward_allowed=forward_allowed)
    folder = args.output_dir
    if folder.is_symlink():
        raise RuntimeError("Output directory must not be a symlink")
    folder.mkdir(mode=0o750, parents=True, exist_ok=True)
    folder.chmod(0o750)
    dest = folder / "config.json"
    payload = config_bytes(config)
    if dest.is_symlink() or (dest.exists() and dest.read_bytes() != payload):
        raise RuntimeError("Refusing to overwrite a different existing configuration")
    if not dest.exists():
        with dest.open("xb") as stream:
            stream.write(payload)
    dest.chmod(0o640)
    if args.check_binary:
        run(str(args.check_binary.resolve()), "check", "-c", str(dest.resolve()))
    print(json.dumps({"rendered": str(dest), "port": args.port,
                      "authorized_clients": len(config["inbounds"][0]["users"])}))


def port_free(listen, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((listen, port))


def install(args):
    if os.geteuid() or platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("Installation requires root on Linux amd64")
    archive_bytes = args.archive.read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != ARCHIVE_SHA256:
        raise RuntimeError("Archive SHA256 does not match the pinned official release")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        member = archive.getmember("sing-box-" + VERSION + "-linux-amd64/sing-box")
        if not member.isfile():
            raise RuntimeError("Release binary is not a regular file")
        binary_bytes = archive.extractfile(member).read()
    inbound = source_inbound(args.source_config, args.source_port)
    forward = source_inbound(args.source_config, args.forward_port, reality=False)
    allowed = enabled_clients(args.database, args.source_port)
    forward_allowed = enabled_clients(args.database, args.forward_port)
    config = build_config(inbound, allowed, args.port, "0.0.0.0",
                          forward_inbound=forward, forward_allowed=forward_allowed)
    payload = config_bytes(config)
    expected = {CONFIG: payload, UNIT: UNIT_TEXT.encode(), RUNTIME / "sing-box": binary_bytes}
    if CONFIG_DIR.is_symlink() or RUNTIME.is_symlink():
        raise RuntimeError("Listener directories must not be symlinks")
    existing = [path for path in expected if path.exists() or path.is_symlink()]
    if existing:
        if len(existing) != len(expected) or any(
                path.is_symlink() or path.read_bytes() != data for path, data in expected.items()):
            raise RuntimeError("Existing listener files differ; an explicit reviewed update is required")
        gid = grp.getgrnam(SERVICE).gr_gid
        modes = {CONFIG_DIR: 0o750, RUNTIME: 0o750, CONFIG: 0o640,
                 UNIT: 0o644, RUNTIME / "sing-box": 0o755}
        if any(path.stat().st_uid != 0 or stat.S_IMODE(path.stat().st_mode) != mode
               or path.stat().st_gid != (0 if path == UNIT else gid)
               for path, mode in modes.items()):
            raise RuntimeError("Existing listener ownership or permissions differ")
        if run("systemctl", "show", "--property=DropInPaths", "--value", SERVICE).strip():
            raise RuntimeError("Existing listener has unexpected systemd overrides")
        run("systemctl", "is-active", "--quiet", SERVICE)
        print("Existing compatible listener is identical and active; no service action performed")
        return
    if CONFIG_DIR.exists() or RUNTIME.exists():
        raise RuntimeError("Listener directories already exist; refusing to overwrite them")
    if subprocess.run(["systemctl", "cat", SERVICE], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError("An existing systemd service has this name")
    port_free("0.0.0.0", args.port)
    with tempfile.TemporaryDirectory(prefix="compatible-vless-") as work:
        temp = Path(work)
        binary = temp / "sing-box"
        binary.write_bytes(binary_bytes)
        binary.chmod(0o700)
        if run(str(binary), "version").splitlines()[0] != ("sing-box version " + VERSION).encode():
            raise RuntimeError("Unexpected sing-box version")
        temp_config = temp / "config.json"
        temp_config.write_bytes(payload)
        temp_config.chmod(0o600)
        run(str(binary), "check", "-c", str(temp_config))
    try:
        grp.getgrnam(SERVICE)
    except KeyError:
        run("groupadd", "--system", SERVICE)
    try:
        account = pwd.getpwnam(SERVICE)
        if (not 0 < account.pw_uid < 1000 or account.pw_gid != grp.getgrnam(SERVICE).gr_gid
                or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")):
            raise RuntimeError("Existing service account is unsuitable")
    except KeyError:
        run("useradd", "--system", "--gid", SERVICE, "--no-create-home",
            "--shell", "/usr/sbin/nologin", SERVICE)
    gid = grp.getgrnam(SERVICE).gr_gid
    created = []
    unit_created = False
    try:
        for folder in (CONFIG_DIR, RUNTIME):
            folder.mkdir(mode=0o750)
            os.chown(folder, 0, gid)
            folder.chmod(0o750)
            created.append(folder)
        for path, data in expected.items():
            with path.open("xb") as stream:
                stream.write(data)
            if path == UNIT:
                unit_created = True
            os.chown(path, 0, gid if path != UNIT else 0)
            path.chmod(0o755 if path.name == "sing-box" else 0o644 if path == UNIT else 0o640)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", SERVICE)
        run("systemctl", "is-active", "--quiet", SERVICE)
        for attempt in range(20):
            try:
                with socket.create_connection(("127.0.0.1", args.port), timeout=1):
                    break
            except OSError:
                if attempt == 19:
                    raise RuntimeError("New listener did not bind its TCP port")
                time.sleep(0.25)
    except BaseException:
        # Cleanup is restricted to files created by this invocation and its new unit.
        if unit_created:
            subprocess.run(["systemctl", "disable", "--now", SERVICE], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            UNIT.unlink()
        for folder in reversed(created):
            shutil.rmtree(folder)
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    print(json.dumps({"installed": SERVICE, "port": args.port,
                      "authorized_clients": len(config["inbounds"][0]["users"])}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("render", "install"):
        item = sub.add_parser(command)
        item.add_argument("--source-config", type=Path, default=Path("/usr/local/x-ui/bin/config.json"))
        item.add_argument("--database", type=Path, default=Path("/etc/x-ui/x-ui.db"))
        item.add_argument("--source-port", type=int, default=33172)
        item.add_argument("--forward-port", type=int, default=46738)
        item.add_argument("--port", type=int, default=33173)
        if command == "render":
            item.add_argument("--output-dir", type=Path, required=True)
            item.add_argument("--listen", default="0.0.0.0")
            item.add_argument("--runtime-only", action="store_true", help="Canary/fixture only: skip panel authorization")
            item.add_argument("--check-binary", type=Path)
        else:
            item.add_argument("--archive", type=Path, required=True,
                              help="Official sing-box-1.14.3-linux-amd64.tar.gz; SHA256 is pinned")
    args = parser.parse_args()
    try:
        render(args) if args.command == "render" else install(args)
    except (RuntimeError, ValueError, OSError, KeyError, sqlite3.Error) as exc:
        # No repr(config), SQL rows, keys, client IDs, or daemon diagnostic dumps.
        parser.exit(1, "compatible-vless: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
