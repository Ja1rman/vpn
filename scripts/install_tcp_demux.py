#!/usr/bin/env python3
"""Install an independent protocol classifier; redirect only new external SYNs.

No original listener/configuration is changed. Rollback removes just the exact
owned NAT rule and leaves the classifier alive to drain established connections.
"""
import argparse
from contextlib import contextmanager
import fcntl
import pwd
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid

from vpn_env import configured_values, load_json

NAME = 'vpn-tcp-demux'
ROOT = Path('/etc') / NAME
BIN = Path('/opt') / NAME / 'tcp-demux'
HELPER = ROOT / 'install_tcp_demux.py'
SETTINGS = ROOT / 'settings.json'
CONFIG = ROOT / 'config.json'
MANIFEST = ROOT / 'manifest.json'
STATE = ROOT / 'transaction.json'
COMMITTED = ROOT / 'committed'
UNITS = Path('/etc/systemd/system')
LOCK = Path('/run/lock') / (NAME + '.lock')
COMMENT = NAME + ':owned'
MAIN_FILES = [Path('/usr/local/x-ui/bin/config.json'), Path('/etc/vpn-failover/pool.json')]
MAIN_BINARIES = {'/usr/local/x-ui/bin/xray-linux-amd64', '/opt/vpn-failover/pool/xray', '/opt/vpn-balancer/xray'}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def command(*args, required=True):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=30)
    need(not required or result.returncode == 0, 'Owned service command failed: ' + str(args[0]))
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def atomic(path, data, mode=0o600):
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            os.chmod(temporary, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def private_json(path):
    info = path.lstat()
    need(path.is_file() and not path.is_symlink() and not info.st_mode & 0o077
         and info.st_size <= 65536, 'Unsafe private settings file')
    return load_json(path)


def settings(value):
    need(isinstance(value, dict) and set(value) == {'address', 'interface', 'public_port', 'listen_port', 'classifier'},
         'Unexpected demux settings schema')
    address = ipaddress.IPv4Address(value['address'])
    need(not (address.is_loopback or address.is_unspecified or address.is_multicast), 'A unicast ingress IPv4 is required')
    need(isinstance(value['interface'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value['interface']),
         'Invalid ingress interface')
    for key in ('public_port', 'listen_port'):
        need(type(value[key]) is int and 1 <= value[key] <= 65535, 'Invalid configured network port')
    need(value['listen_port'] >= 1024 and value['listen_port'] != value['public_port'],
         'The independent listener needs a distinct unprivileged port')
    config = value['classifier']
    need(isinstance(config, dict) and config.get('listen') == str(address) + ':' + str(value['listen_port'])
         and config.get('redirected_from') == str(address) + ':' + str(value['public_port']),
         'Classifier endpoint guard differs from NAT settings')
    original_host, original_port = config.get('default_target', '').rsplit(':', 1)
    need(ipaddress.IPv4Address(original_host).is_loopback and original_port == str(value['public_port']),
         'The default must retain the original loopback listener')
    return value


def nat_settings(value):
    result = {key: value[key] for key in ('address', 'interface', 'public_port', 'listen_port')}
    ip = ipaddress.IPv4Address(result['address'])
    need(not (ip.is_loopback or ip.is_unspecified or ip.is_multicast), 'Invalid sealed ingress address')
    need(re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', result['interface']), 'Invalid sealed ingress interface')
    need(all(type(result[k]) is int and 1 <= result[k] <= 65535 for k in ('public_port','listen_port'))
         and result['listen_port'] >= 1024 and result['public_port'] != result['listen_port'], 'Invalid sealed ingress ports')
    return result


def rule(value, drain=False):
    args = ['-i', value['interface'], '-d', value['address'] + '/32', '-p', 'tcp', '--syn',
            '--dport', str(value['public_port']), '-m', 'conntrack', '--ctstate', 'INVALID' if drain else 'NEW',
            '-m', 'comment', '--comment', COMMENT + ('-drain' if drain else ''), '-j', 'RETURN' if drain else 'REDIRECT']
    return args if drain else args + ['--to-ports', str(value['listen_port'])]


def present(value, drain=False):
    saved = command('iptables-save', '-t', 'nat').stdout.decode()
    marker = COMMENT + ('-drain' if drain else '')
    matches = []
    for line in saved.splitlines():
        parts = shlex.split(line)
        if '--comment' in parts and parts[parts.index('--comment') + 1] == marker:
            matches.append(line)
    exact = command('iptables', '-w', '5', '-t', 'nat', '-C', 'PREROUTING', *rule(value, drain), required=False).returncode == 0
    need(len(matches) == int(exact), 'An unexpected rule uses the owned firewall marker')
    return exact


def add(value, drain=False):
    if not present(value, drain):
        command('iptables', '-w', '5', '-t', 'nat', '-I', 'PREROUTING', '1', *rule(value, drain))
    need(present(value, drain), 'The exact owned NAT rule was not installed')


def remove(value, drain=False):
    if present(value, drain):
        command('iptables', '-w', '5', '-t', 'nat', '-D', 'PREROUTING', *rule(value, drain))
    need(not present(value, drain), 'The owned NAT rule remained after removal')


def active_connections(value):
    count = 0
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[1].split(':')[1], 16) == value['listen_port'] and fields[3] not in ('0A', '06'):
            count += 1
    return count


def detach(value):
    # Removing a final NAT hook can reset live redirected flows. An INVALID/SYN
    # rule cannot redirect a legitimate new flow; retain it only while draining.
    if present(value):
        add(value, drain=True)
        remove(value)
    draining = active_connections(value) > 0
    if not draining:
        remove(value, drain=True)
    return draining


def readiness(value):
    with socket.create_connection((value['address'], value['listen_port']), timeout=3):
        pass


def snapshot():
    files = {str(path): digest(path.read_bytes()) for path in MAIN_FILES if path.is_file()}
    processes = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            executable = os.readlink(path / 'exe')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if executable in MAIN_BINARIES:
            processes[path.name] = executable
    return {'files': files, 'processes': processes}


def preflight(value):
    interfaces = json.loads(command('ip', '-j', 'addr', 'show', 'dev', value['interface']).stdout)
    need(len(interfaces) == 1 and 'LOOPBACK' not in interfaces[0].get('flags', [])
         and any(item.get('local') == value['address'] for item in interfaces[0].get('addr_info', [])),
         'The configured ingress IPv4 is not on the selected interface')
    host, target = value['classifier']['default_target'].rsplit(':', 1)
    with socket.create_connection((host, int(target)), timeout=3):
        pass


def identity(create=False):
    try:
        user = pwd.getpwnam(NAME)
    except KeyError:
        user = None
    try:
        group = grp.getgrnam(NAME)
    except KeyError:
        group = None
    created = False
    if user is None:
        need(group is None, 'An unrelated group owns the classifier account name')
        need(create, 'The dedicated classifier account is missing')
        command('useradd', '--system', '--user-group', '--home-dir', '/nonexistent',
                '--no-create-home', '--shell', '/usr/sbin/nologin', NAME)
        user, group = pwd.getpwnam(NAME), grp.getgrnam(NAME)
        created = True
    need(group is not None and user.pw_uid > 0 and user.pw_gid == group.gr_gid
         and user.pw_dir == '/nonexistent' and user.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin'),
         'An unrelated account owns the classifier user name')
    return {'uid': user.pw_uid, 'gid': group.gr_gid, 'created': created}


def remove_created_identity(account):
    if not account.get('created'):
        return
    current = identity()
    need(current['uid'] == account['uid'] and current['gid'] == account['gid'],
         'The newly created classifier account changed during installation')
    command('userdel', NAME, required=False)
    try:
        group = grp.getgrnam(NAME)
    except KeyError:
        return
    if group.gr_gid == account['gid'] and not group.gr_mem:
        command('groupdel', NAME, required=False)


def service_unit():
    return f'''[Unit]
Description=Independent protocol classifier for new proxy connections
After=network-online.target
Wants=network-online.target {NAME}-firewall.service
[Service]
Type=simple
User={NAME}
Group={NAME}
ExecStart={BIN} -config {CONFIG}
Restart=on-failure
RestartSec=3
TimeoutStopSec=infinity
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
LimitNOFILE=4096
TasksMax=128
MemoryMax=128M
Environment=GOMEMLIMIT=96MiB GOMAXPROCS=2
CPUQuota=100%
[Install]
WantedBy=multi-user.target
'''.encode()


def firewall_unit():
    return f'''[Unit]
Description=Restore the committed classifier ingress rule
After=network-online.target {NAME}.service x-ui.service docker.service
Wants=network-online.target
Requires={NAME}.service
BindsTo={NAME}.service
ConditionPathExists={COMMITTED}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={sys.executable} {HELPER} restore
ExecStop={sys.executable} {HELPER} deactivate
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
'''.encode()


@contextmanager
def locked():
    with LOCK.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def installed():
    value = settings(private_json(SETTINGS))
    account = identity()
    need(CONFIG.stat().st_uid == account['uid'] and CONFIG.stat().st_mode & 0o777 == 0o600
         and ROOT.stat().st_gid == account['gid'] and ROOT.stat().st_mode & 0o777 == 0o750,
         'Dedicated classifier configuration permissions changed')
    manifest = private_json(MANIFEST)
    expected = {'binary': digest(BIN.read_bytes()), 'config': digest(CONFIG.read_bytes()),
                'settings': digest(SETTINGS.read_bytes()), 'service': digest((UNITS / (NAME + '.service')).read_bytes()),
                'firewall': digest((UNITS / (NAME + '-firewall.service')).read_bytes()),
                'helper':digest(HELPER.read_bytes()),'env_module':digest((ROOT/'vpn_env.py').read_bytes()),
                'env_config':digest((ROOT/'vpn.env.json').read_bytes())}
    need(manifest == expected, 'Installed owned files differ from their manifest')
    return value


def install(source, checksum, value):
    value = settings(value)
    data = source.read_bytes()
    need(re.fullmatch(r'[a-f0-9]{64}', checksum) and digest(data) == checksum, 'Classifier binary checksum mismatch')
    preflight(value)
    if ROOT.exists() or BIN.parent.exists() or (UNITS / (NAME + '.service')).exists() or (UNITS / (NAME + '-firewall.service')).exists():
        current = installed()
        need(current == value and digest(BIN.read_bytes()) == checksum, 'A different owned installation already exists')
        need(command('systemctl', 'is-active', NAME + '.service', required=False).returncode == 0,
             'The existing owned service is not active; explicit investigation required')
        return {'already_installed': True}
    before = snapshot()
    with socket.socket() as probe:
        probe.bind((value['address'], value['listen_port']))
    created = []
    account = {'created': False}
    try:
        account = identity(create=True)
        for path in (ROOT, BIN.parent):
            path.mkdir(mode=0o700); created.append(path)
        ROOT.chmod(0o750); os.chown(ROOT, 0, account['gid'])
        atomic(BIN, data, 0o755)
        BIN.parent.chmod(0o755)
        atomic(CONFIG, encode(value['classifier']))
        os.chown(CONFIG, account['uid'], account['gid'])
        atomic(SETTINGS, encode(value))
        atomic(HELPER, Path(__file__).read_bytes())
        atomic(ROOT / 'vpn_env.py', Path(__file__).with_name('vpn_env.py').read_bytes())
        atomic(ROOT / 'vpn.env.json', encode(configured_values()))
        command(BIN, '-check', '-config', CONFIG)
        for filename, content in ((NAME + '.service', service_unit()), (NAME + '-firewall.service', firewall_unit())):
            path = UNITS / filename
            need(not path.exists(), 'An unexpected unit appeared during installation')
            with path.open('xb') as stream:
                os.chmod(path, 0o644); stream.write(content)
            created.append(path)
        atomic(MANIFEST, encode({'binary': checksum, 'config': digest(CONFIG.read_bytes()),
                                'settings': digest(SETTINGS.read_bytes()), 'service': digest(service_unit()),
                                'firewall': digest(firewall_unit()),'helper':digest(HELPER.read_bytes()),
                                'env_module':digest((ROOT/'vpn_env.py').read_bytes()),'env_config':digest((ROOT/'vpn.env.json').read_bytes())}))
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', NAME + '.service')
        for _ in range(40):
            if command('systemctl', 'is-active', NAME + '.service', required=False).returncode == 0:
                try:
                    readiness(value); break
                except OSError:
                    pass
            time.sleep(.1)
        need(command('systemctl', 'is-active', NAME + '.service', required=False).returncode == 0,
             'The new classifier did not start')
        readiness(value)
        need(snapshot() == before, 'An original VPN process/configuration changed during installation')
        return {'installed': True, 'public_redirect_active': False}
    except BaseException:
        if UNITS / (NAME + '.service') in created:
            command('systemctl', 'disable', '--now', NAME + '.service', required=False)
        for path in reversed(created):
            shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True)
        command('systemctl', 'daemon-reload', required=False)
        remove_created_identity(account)
        raise


def sealed_state():
    state = private_json(STATE)
    need(STATE.lstat().st_uid == os.geteuid() and ROOT.lstat().st_uid == os.geteuid(), 'Unexpected rollback state owner')
    nat_settings(state['nat_settings'])
    return state


def rollback(transaction=None):
    state = sealed_state()
    if transaction:
        need(state['id'] == transaction, 'A different transaction owns the rollback')
        if state['status'] != 'armed':
            return {'rollback_needed': False}
    draining = detach(state['nat_settings'])
    COMMITTED.unlink(missing_ok=True)
    state.update(status='rolled_back', draining=draining)
    atomic(STATE, encode(state))
    command('systemctl', 'disable', NAME + '-firewall.service', required=False)
    command('systemctl', '--no-block', 'stop', NAME + '-firewall.service', required=False)
    if draining:
        subprocess.Popen([sys.executable, str(HELPER), 'drain', '--transaction', state['id']],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, close_fds=True)
    return {'rolled_back': True, 'classifier_kept_for_existing_connections': True, 'draining': draining}


def apply():
    value = installed()
    preflight(value)
    readiness(value)
    need(command('systemctl', 'is-active', NAME + '.service', required=False).returncode == 0,
         'The owned classifier must already be active')
    if COMMITTED.exists():
        need(present(value), 'The committed rule is missing; use restore explicitly')
        return {'already_committed': True}
    if STATE.exists():
        state = private_json(STATE)
        if state['status'] == 'armed':
            need(state['deadline'] > time.time() and present(value) and state['settings'] == digest(SETTINGS.read_bytes())
                 and snapshot() == state['baseline'], 'A pending transaction requires rollback')
            return {'armed': True, 'transaction': state['id']}
    need(not present(value), 'An uncommitted rule already exists')
    state = {'id': uuid.uuid4().hex, 'status': 'armed', 'deadline': time.time() + 180,
             'baseline': snapshot(), 'settings': digest(SETTINGS.read_bytes()), 'nat_settings': nat_settings(value)}
    atomic(STATE, encode(state))
    subprocess.Popen([sys.executable, str(HELPER), 'watchdog', '--transaction', state['id']],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True, close_fds=True)
    try:
        add(value)
        remove(value, drain=True)
        need(snapshot() == state['baseline'], 'An original VPN process/configuration changed during apply')
    except BaseException:
        rollback(state['id']); raise
    return {'armed': True, 'transaction': state['id'], 'watchdog_seconds': 180}


def commit(proof):
    value = installed(); state = private_json(STATE)
    need(state['status'] == 'armed' and time.time() < state['deadline'], 'The transaction is not armed')
    need(proof.get('transaction') == state['id'], 'The external proof belongs to a different transaction')
    need(proof.get('original_tls') is True and proof.get('new_protocols') is True,
         'External original-TLS and native new-protocol proofs are required')
    need(state['settings'] == digest(SETTINGS.read_bytes()) and snapshot() == state['baseline'] and present(value),
         'Original runtime or owned ingress changed during verification')
    atomic(COMMITTED, (state['id'] + '\n').encode())
    state.update(status='committed', proofs={'original_tls': True, 'new_protocols': True})
    atomic(STATE, encode(state))
    return {'committed': True, 'original_runtime_unchanged': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'install', 'apply', 'commit', 'rollback', 'watchdog', 'restore', 'deactivate', 'drain'])
    parser.add_argument('--settings', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--proof-file', type=Path)
    parser.add_argument('--transaction')
    args = parser.parse_args()
    if args.action == 'plan':
        need(args.settings is not None, 'A private settings file is required')
        preflight(settings(private_json(args.settings)))
        print(json.dumps({'settings_valid': True, 'original_listener_available': True})); return
    need(os.geteuid() == 0, 'This action requires root')
    if args.action in ('watchdog', 'drain'):
        while True:
            with locked():
                state = sealed_state()
                if state['id'] != args.transaction or (args.action == 'watchdog' and state['status'] != 'armed'):
                    return
                if args.action == 'drain':
                    if state['status'] != 'rolled_back':
                        return
                    if not active_connections(state['nat_settings']):
                        remove(state['nat_settings'], drain=True)
                        state['draining'] = False; atomic(STATE, encode(state)); return
                elif time.time() >= state['deadline'] or command('systemctl', 'is-active', NAME + '.service', required=False).returncode != 0:
                    rollback(args.transaction); return
            time.sleep(1)
    with locked():
        if args.action == 'install':
            need(args.settings and args.binary and args.sha256, 'Binary, checksum and private settings are required')
            result = install(args.binary, args.sha256, private_json(args.settings))
        elif args.action == 'apply': result = apply()
        elif args.action == 'commit':
            need(args.proof_file is not None, 'A private external proof file is required')
            result = commit(private_json(args.proof_file))
        elif args.action in ('rollback', 'watchdog'): result = rollback(args.transaction)
        elif args.action == 'restore':
            value = installed()
            need(COMMITTED.exists(), 'The classifier has not been committed')
            preflight(value); readiness(value); add(value); remove(value, drain=True); result = {'committed_redirect_restored': True}
        else:
            state=sealed_state(); draining=detach(state['nat_settings']); result = {'owned_rule_removed': True, 'draining': draining}
    if args.action == 'commit':
        try:
            command('systemctl', 'enable', '--now', NAME + '-firewall.service')
        except BaseException:
            with locked(): rollback()
            raise
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        print(json.dumps({'passed': False, 'error': detail}), file=sys.stderr)
        sys.exit(1)
