#!/usr/bin/env python3
"""Install only the independent failover subscription and its certificate timer."""
import argparse
from contextlib import closing
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import tempfile
import time


NAME = "vpn-failover-subscription"
SERVICE = NAME + ".service"
CERT_SERVICE = NAME + "-cert.service"
CERT_TIMER = NAME + "-cert.timer"
ADDRESS, PORT = "212.22.70.156", 2097
CONFIG = Path("/etc") / NAME
RUNTIME = Path("/opt") / NAME
TLS = CONFIG / "tls.pem"
DATABASE = Path("/etc/x-ui/x-ui.db")
UNITS = Path("/etc/systemd/system")
INSTALLER = RUNTIME / "install_failover_subscription.py"
APPLICATION = RUNTIME / "failover_subscription.py"
NOLOGIN = "/usr/sbin/nologin"

SERVICE_TEXT = f"""[Unit]
Description=VPN one-profile failover subscription
After=network-online.target
Wants=network-online.target
[Service]
User={NAME}
Group={NAME}
ExecStart=/usr/bin/python3 -B {APPLICATION} --port {PORT} --tls-cert {TLS} --tls-key {TLS}
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
RestrictAddressFamilies=AF_UNIX AF_INET
LockPersonality=true
MemoryMax=128M
UMask=0077
[Install]
WantedBy=multi-user.target
"""
CERT_TEXT = f"""[Unit]
Description=Copy the renewed x-ui certificate for the failover subscription
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 -B {INSTALLER} sync-certificate
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={CONFIG}
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX
UMask=0077
"""
TIMER_TEXT = f"""[Unit]
Description=Check the failover subscription certificate copy
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=15s
Unit={CERT_SERVICE}
[Install]
WantedBy=timers.target
"""


def command(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError("Command failed: " + " ".join(args[:2]))
    return result.stdout


def read_root_file(filename, *, private=False, limit=1024 * 1024):
    """Read only the actual regular file explicitly named in x-ui settings."""
    path = Path(filename)
    if not filename or not path.is_absolute():
        raise RuntimeError("x-ui must specify an absolute subscription certificate and key path")
    real = path.resolve(strict=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(real, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (private and info.st_mode & 0o007)):
            raise RuntimeError("x-ui subscription TLS file has unsafe type, owner or permissions")
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise RuntimeError("x-ui subscription TLS file is empty or too large")
    return data


def source_certificate(database):
    uri = database.resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=6)) as db:
        settings = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('subCertFile','subKeyFile')"))
    cert = read_root_file(settings.get("subCertFile") or "")
    key = read_root_file(settings.get("subKeyFile") or "", private=True)
    combined = cert.rstrip() + b"\n"
    if key != cert:
        combined += key.rstrip() + b"\n"
    return cert, combined


def write_exclusive(path, data, *, mode=0o600, group=0):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def validate_certificate(chain, pair, address=ADDRESS, ca_file=None):
    command("openssl", "x509", "-in", str(chain), "-noout", "-checkend", "300")
    # Some OpenSSL versions report -checkip mismatches without a failing status.
    command("openssl", "x509", "-in", str(chain), "-noout", "-checkip", address)
    trust = ["-CAfile", str(ca_file)] if ca_file else []
    command("openssl", "verify", "-purpose", "sslserver", "-verify_ip", address,
            *trust, "-untrusted", str(chain), str(chain))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(pair, pair, password=lambda: "")
    except ssl.SSLError:
        raise RuntimeError("x-ui subscription TLS certificate and private key do not match") from None


def check_account():
    user = pwd.getpwnam(NAME)
    group = grp.getgrnam(NAME)
    if (not 0 < user.pw_uid < 1000 or not group.gr_gid or user.pw_gid != group.gr_gid
            or user.pw_shell != NOLOGIN or set(group.gr_mem) - {NAME}
            or any(u.pw_gid == group.gr_gid and u.pw_name != NAME for u in pwd.getpwall())):
        raise RuntimeError("The dedicated subscription service account has an unexpected configuration")
    return group.gr_gid


def sync_certificate():
    gid = check_account()
    directory = os.open(CONFIG, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
            raise RuntimeError("Unexpected ownership or permissions on the private TLS directory")
        fcntl.flock(directory, fcntl.LOCK_EX)
        cert, data = source_certificate(DATABASE)
        if TLS.is_symlink():
            raise RuntimeError("Refusing a symlink as the subscription TLS copy")
        if TLS.exists():
            old = TLS.stat()
            if not stat.S_ISREG(old.st_mode) or old.st_uid != 0:
                raise RuntimeError("Existing TLS copy is not a root-owned regular file")
            if (old.st_gid == gid and stat.S_IMODE(old.st_mode) == 0o640
                    and old.st_size == len(data) and TLS.read_bytes() == data):
                command("openssl", "x509", "-in", str(TLS), "-noout", "-checkend", "300")
                return False
        with tempfile.TemporaryDirectory(prefix=".certificate-", dir=CONFIG) as staging:
            chain, pair = Path(staging) / "chain.pem", Path(staging) / "tls.pem"
            write_exclusive(chain, cert)
            write_exclusive(pair, data, mode=0o640, group=gid)
            validate_certificate(chain, pair)
            os.replace(pair, TLS)
            os.fsync(directory)
        return True
    finally:
        os.close(directory)


def unit_is_absent(unit):
    state = command("systemctl", "show", "--property=LoadState", "--value", unit).strip()
    return state == b"not-found"


def account_is_absent():
    try:
        pwd.getpwnam(NAME)
    except KeyError:
        pass
    else:
        return False
    try:
        grp.getgrnam(NAME)
    except KeyError:
        return True
    return False


def probe_listener():
    trust = ssl.create_default_context()
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=2) as raw:
                with trust.wrap_socket(raw, server_hostname=ADDRESS):
                    return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("The new subscription port did not answer with a trusted TLS certificate")


def install(source):
    code = source.read_bytes()
    # Syntax check without importing or starting the application as root.
    compile(code, APPLICATION.name, "exec")
    payload = {APPLICATION: code, INSTALLER: Path(__file__).read_bytes(),
               UNITS / SERVICE: SERVICE_TEXT.encode(), UNITS / CERT_SERVICE: CERT_TEXT.encode(),
               UNITS / CERT_TIMER: TIMER_TEXT.encode()}
    if RUNTIME.is_symlink() or CONFIG.is_symlink() or any(path.is_symlink() for path in payload):
        raise RuntimeError("Refusing to install through a symlink")
    existing = [path for path in payload if path.exists()]
    if existing:
        if len(existing) != len(payload) or any(not path.is_file() or path.read_bytes() != data
                                                 for path, data in payload.items()):
            raise RuntimeError("Subscription files already exist and differ; no files were overwritten")
        gid = check_account()
        for path in (*payload, RUNTIME):
            info = path.stat()
            is_unit = path.parent == UNITS
            mode = 0o644 if is_unit else (0o750 if path == RUNTIME else 0o640)
            if info.st_uid != 0 or info.st_gid != (0 if is_unit else gid) or stat.S_IMODE(info.st_mode) != mode:
                raise RuntimeError("Subscription files already exist with unexpected ownership or permissions")
        for unit in (SERVICE, CERT_TIMER):
            command("systemctl", "is-active", "--quiet", unit)
        return {"installed": False, "certificate_changed": sync_certificate()}
    if (RUNTIME.exists() or CONFIG.exists() or not account_is_absent()
            or not all(unit_is_absent(unit) for unit in (SERVICE, CERT_SERVICE, CERT_TIMER))):
        raise RuntimeError("Dedicated subscription paths, account or systemd unit names are already in use")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("0.0.0.0", PORT))
    dirs, units = [], []
    user_created = group_created = False
    try:
        command("groupadd", "--system", NAME)
        group_created = True
        command("useradd", "--system", "--gid", NAME, "--no-create-home", "--home-dir", "/nonexistent",
                "--shell", NOLOGIN, NAME)
        user_created = True
        gid = check_account()
        for folder in (CONFIG, RUNTIME):
            folder.mkdir(mode=0o750)
            dirs.append(folder)
            os.chown(folder, 0, gid)
            folder.chmod(0o750)
        sync_certificate()
        for path, data in payload.items():
            is_unit = path.parent == UNITS
            # Record unit ownership immediately after O_EXCL succeeds, so a partial write is cleaned up.
            if is_unit:
                with path.open("xb") as stream:
                    units.append(path)
                    stream.write(data)
                path.chmod(0o644)
            else:
                write_exclusive(path, data, mode=0o640, group=gid)
        command("systemctl", "daemon-reload")
        command("systemctl", "enable", "--now", SERVICE, CERT_TIMER)
        for unit in (SERVICE, CERT_TIMER):
            command("systemctl", "is-active", "--quiet", unit)
        probe_listener()
    except BaseException:
        for unit in (CERT_TIMER, SERVICE, CERT_SERVICE):
            if UNITS / unit in units:
                action = ["stop"] if unit == CERT_SERVICE else ["disable", "--now"]
                subprocess.run(["systemctl", *action, unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in units:
            path.unlink(missing_ok=True)
        if units:
            subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for folder in reversed(dirs):
            shutil.rmtree(folder)
        if user_created:
            subprocess.run(["userdel", NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if group_created:
            subprocess.run(["groupdel", NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    return {"installed": True, "port": PORT, "certificate_changed": True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("install")
    setup.add_argument("--service-script", type=Path,
                       default=Path(__file__).with_name("failover_subscription.py"))
    commands.add_parser("sync-certificate")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
            raise RuntimeError("Run as root on a host with systemd")
        result = install(args.service_script) if args.command == "install" else {
            "certificate_changed": sync_certificate()}
        print(json.dumps(result))
    except RuntimeError as exc:
        parser.exit(1, "failover subscription: " + str(exc) + "\n")
    except (OSError, ValueError, KeyError, SyntaxError, sqlite3.Error, subprocess.SubprocessError) as exc:
        parser.exit(1, "failover subscription: operation failed (" + type(exc).__name__ + ")\n")


if __name__ == "__main__":
    main()
