#!/usr/bin/env python3
"""Install the independent VPN Auto VLESS/TLS frontend; never restart an old entry."""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import time


NAME = 'vpn-auto-tls-frontend'
UNIT = NAME + '.service'
CONTAINER = NAME
LABEL = 'org.vpn-infra.role=' + NAME
IMAGE = 'nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5'
DOCKER = '/usr/bin/docker'
DOCKER_HOST = '--host=unix:///var/run/docker.sock'
ADDRESS = '212.22.70.156'
PORT = 33175
UPSTREAM = '127.0.0.1'
UPSTREAM_PORT = 46738
SOURCE_IP = '127.0.0.2'
SUBSCRIPTION = 'vpn-failover-subscription'
CERT_DIRECTORY = Path('/etc') / SUBSCRIPTION
TLS = CERT_DIRECTORY / 'tls.pem'
CERT_IN_CONTAINER = '/etc/vpn-subscription/tls.pem'
CONFIG = Path('/etc') / NAME
RUNTIME = Path('/opt') / NAME
APPLICATION = RUNTIME / 'install_auto_tls_frontend.py'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
CIDFILE = Path('/run') / NAME / 'container.cid'
MAIN_CONFIG = Path('/usr/local/x-ui/bin/config.json')
MAIN_XRAY = MAIN_CONFIG.with_name('xray-linux-amd64')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, timeout=25, include_stderr=False):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Command timed out: ' + ' '.join(args[:2])) from None
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:2]))
    return result.stdout + result.stderr if include_stderr else result.stdout


def stream_module(version):
    flags = version.split()
    require('--with-stream_ssl_module' in flags, 'The pinned nginx image has no stream SSL support')
    if '--with-stream' in flags:
        return ''
    require('--with-stream=dynamic' in flags, 'The pinned nginx image has no stream support')
    modules = next((flag.split('=', 1)[1] for flag in flags if flag.startswith('--modules-path=')), '')
    require(re.fullmatch(r'/[a-zA-Z0-9/_-]+', modules), 'Unexpected nginx module directory')
    return 'load_module ' + modules.rstrip('/') + '/ngx_stream_module.so;\n'


def nginx_config(load_module='', *, port=PORT, upstream_port=UPSTREAM_PORT, source=SOURCE_IP,
                 listen='0.0.0.0', certificate=CERT_IN_CONTAINER, pid_path='/tmp/nginx.pid'):
    return f"""{load_module}worker_processes 1;
pid {pid_path};
lock_file /tmp/vpn-auto-nginx.lock;
error_log /dev/null crit;
events {{ worker_connections 2048; }}
stream {{
    access_log off;
    limit_conn_zone $server_port zone=auto_tls_sessions:1m;
    map $ssl_server_name $vpn_certificate {{
        default {certificate};
    }}
    server {{
        listen {listen}:{port} ssl;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_handshake_timeout 8s;
        ssl_certificate $vpn_certificate;
        ssl_certificate_key $vpn_certificate;
        ssl_certificate_cache max=2 inactive=1m valid=30s;
        ssl_session_cache shared:auto_tls_session_cache:1m;
        ssl_session_tickets off;
        limit_conn auto_tls_sessions 512;
        proxy_pass {UPSTREAM}:{upstream_port};
        proxy_bind {source};
        proxy_connect_timeout 3s;
        proxy_timeout 15m;
        proxy_socket_keepalive on;
        proxy_half_close on;
    }}
}}
"""


def container_args(uid, gid, conf=CONFIG / 'nginx.conf', cert_folder=CERT_DIRECTORY):
    return [
        '--pull=never', '--network=host', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user', f'{uid}:{gid}',
        '--memory=96m', '--cpus=0.5', '--pids-limit=24', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777',
        '--mount', f'type=bind,source={conf},target=/etc/nginx/nginx.conf,readonly',
        '--mount', f'type=bind,source={cert_folder},target=/etc/vpn-subscription,readonly',
        '--entrypoint', '/usr/sbin/nginx', IMAGE,
    ]


def unit_text(uid, gid):
    args = ' '.join(container_args(uid, gid))
    return f"""[Unit]
Description=Independent VPN Auto TLS frontend for x-ui clients
Requires=docker.service
Wants=network-online.target
After=docker.service network-online.target x-ui.service vpn-failover-pool.service
[Service]
Type=simple
RuntimeDirectory={NAME}
RuntimeDirectoryMode=0700
ExecStart={DOCKER} {DOCKER_HOST} run --rm --name {CONTAINER} --cidfile {CIDFILE} --label {LABEL} --log-driver=none {args} -e /dev/null -g "daemon off;"
ExecStop=/usr/bin/python3 -B {APPLICATION} stop-container
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def certificate_account():
    account = pwd.getpwnam(SUBSCRIPTION)
    group = grp.getgrnam(SUBSCRIPTION)
    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid and group.gr_gid > 0,
            'The existing certificate reader must have its own non-root account')
    info = CERT_DIRECTORY.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == group.gr_gid
            and stat.S_IMODE(info.st_mode) == 0o750, 'Unexpected subscription certificate directory permissions')
    info = TLS.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == group.gr_gid
            and stat.S_IMODE(info.st_mode) == 0o640, 'Unexpected subscription certificate permissions')
    return account.pw_uid, group.gr_gid


def validate_certificate():
    command('openssl', 'x509', '-in', str(TLS), '-noout', '-checkend', '300')
    command('openssl', 'verify', '-purpose', 'sslserver', '-verify_ip', ADDRESS,
            '-untrusted', str(TLS), str(TLS))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(TLS, TLS, password=lambda: '')
    except ssl.SSLError:
        raise RuntimeError('The trusted IP certificate and key do not match') from None


def validate_backend(config):
    tag = 'in-46738-tcp'
    inbounds = [i for i in config['inbounds'] if i.get('tag') == tag]
    require(len(inbounds) == 1, 'Expected one main Xray VLESS inbound')
    inbound = inbounds[0]
    stream = inbound.get('streamSettings', {})
    transport = stream.get('rawSettings') or stream.get('tcpSettings') or {}
    require(inbound.get('protocol') == 'vless' and inbound.get('port') == UPSTREAM_PORT
            and inbound.get('settings', {}).get('decryption') == 'none'
            and inbound.get('listen') in ('', '127.0.0.1', '0.0.0.0', '::')
            and stream.get('network') in ('raw', 'tcp') and stream.get('security', 'none') == 'none'
            and transport.get('header', {}).get('type', 'none') == 'none'
            and not transport.get('acceptProxyProtocol')
            and not stream.get('sockopt', {}).get('acceptProxyProtocol'),
            'Main Xray inbound is not compatible with raw VLESS forwarding')
    expected = {'type': 'field', 'ruleTag': 'vpn-failover-source-127-0-0-2', 'inboundTag': [tag],
                'source': [SOURCE_IP + '/32'], 'outboundTag': 'vpn-failover-egress-pool'}
    rules = config['routing']['rules']
    matched = [r for r in rules if r.get('ruleTag') == expected['ruleTag']]
    outbounds = [o for o in config['outbounds'] if o.get('tag') == expected['outboundTag']]
    legacy = {'type': 'field', 'inboundTag': [tag], 'outboundTag': 'vpn-egress-pool'}
    require(matched == [expected] and outbounds == [{'tag': expected['outboundTag'], 'protocol': 'socks',
            'settings': {'address': UPSTREAM, 'port': 11092}}]
            and rules.count(legacy) == 1 and rules.index(expected) + 1 == rules.index(legacy),
            'Existing VPN Auto routing is unexpected')
    return [(r.get('outboundTag', ''), r.get('ruleTag', '')) for r in rules]


def check_backend():
    expected = validate_backend(json.loads(MAIN_CONFIG.read_bytes()))
    live = json.loads(command(str(MAIN_XRAY), 'api', 'lsrules', '--server=127.0.0.1:62789'))
    require([(r.get('tag', ''), r.get('ruleTag', '')) for r in live['rules']] == expected,
            'The live main Xray routing differs from its saved configuration')
    try:
        with socket.create_connection((UPSTREAM, UPSTREAM_PORT), timeout=2, source_address=(SOURCE_IP, 0)):
            pass
    except OSError:
        raise RuntimeError('The main VLESS backend is unreachable from the VPN Auto source address') from None


def write_new(path, data, mode):
    with path.open('xb') as stream:
        try:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise


def verify_listener():
    trust = ssl.create_default_context()
    for _ in range(24):
        try:
            with socket.create_connection((UPSTREAM, PORT), timeout=1.5) as raw:
                with trust.wrap_socket(raw, server_hostname=ADDRESS):
                    return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError('The new frontend did not answer with a trusted IP certificate')


def inspect_owned(cid):
    require(re.fullmatch(r'[a-f0-9]{64}', cid), 'Unexpected frontend container ID')
    result = subprocess.run([DOCKER, DOCKER_HOST, 'container', 'inspect',
                             '--format', '{{json .Config.Labels}} {{.State.Running}}', cid],
                            capture_output=True, timeout=8)
    if result.returncode:
        return None
    labels, running = result.stdout.decode().strip().rsplit(' ', 1)
    require(json.loads(labels).get('org.vpn-infra.role') == NAME, 'Unexpected frontend container ownership')
    return running == 'true'


def check_container():
    require(CIDFILE.is_file() and inspect_owned(CIDFILE.read_text().strip()), 'The new TLS container is not running')


def stop_container():
    if not CIDFILE.exists():
        return
    cid = CIDFILE.read_text().strip()
    if inspect_owned(cid):
        command(DOCKER, DOCKER_HOST, 'stop', '--signal=SIGQUIT', '--time=18', cid)


def install():
    uid, gid = certificate_account()
    validate_certificate()
    check_backend()
    command(DOCKER, DOCKER_HOST, 'image', 'inspect', IMAGE)
    version = command(DOCKER, DOCKER_HOST, 'run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
                      '--user', f'{uid}:{gid}', '--entrypoint', '/usr/sbin/nginx', IMAGE, '-V', include_stderr=True).decode()
    data = {CONFIG / 'nginx.conf': (nginx_config(stream_module(version)).encode(), 0o644),
            APPLICATION: (Path(__file__).read_bytes(), 0o600), UNIT_PATH: (unit_text(uid, gid).encode(), 0o644)}
    if any(os.path.lexists(p) for p in [CONFIG, RUNTIME, UNIT_PATH]):
        require(not any(p.is_symlink() for p in [CONFIG, RUNTIME, *data])
                and all(p.is_file() and p.read_bytes() == value for p, (value, _) in data.items()),
                'A different TLS frontend installation already exists; no files changed')
        command('systemctl', 'is-active', '--quiet', UNIT)
        verify_listener()
        check_container()
        print(UNIT + ' already active; no changes applied')
        return
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The frontend service name is already in use')
    names = command(DOCKER, DOCKER_HOST, 'container', 'ls', '-a', '--format', '{{.Names}}').decode().splitlines()
    require(CONTAINER not in names, 'The frontend container name is already in use')
    with socket.socket() as listener:
        listener.bind(('0.0.0.0', PORT))
    created = []
    daemon_loaded = start_attempted = False
    try:
        for folder in (CONFIG, RUNTIME):
            folder.mkdir(mode=0o700)
            created.append(folder)
        for path, (value, mode) in data.items():
            write_new(path, value, mode)
            created.append(path)
        command(DOCKER, DOCKER_HOST, 'run', '--rm', *container_args(uid, gid), '-e', '/dev/null', '-t')
        command('systemctl', 'daemon-reload')
        daemon_loaded = True
        start_attempted = True
        command('systemctl', 'enable', '--now', UNIT)
        verify_listener()
        command('systemctl', 'is-active', '--quiet', UNIT)
        check_container()
    except BaseException:
        if start_attempted:
            command('systemctl', 'disable', '--now', UNIT)
        for path in reversed(created):
            shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True)
        if daemon_loaded:
            command('systemctl', 'daemon-reload')
        raise
    print(f'{UNIT} is serving trusted TLS on {PORT}; existing VPN services were not restarted')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'stop-container'))
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'Run the installer as root on the entry server')
        install() if args.action == 'install' else stop_container()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'install-auto-tls: ' + detail + '\n')


if __name__ == '__main__':
    main()
