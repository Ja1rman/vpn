#!/usr/bin/env python3
"""Add trusted-TLS wrappers to existing VLESS entries without changing Xray."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time

from install_auto_tls_frontend import (
    ADDRESS, CERT_DIRECTORY, CERT_IN_CONTAINER, DOCKER, DOCKER_HOST, IMAGE,
    MAIN_CONFIG, MAIN_XRAY, certificate_account, command, require,
    environment_payload, refresh_runtime_helpers, running_identity,
    stream_module, validate_certificate, write_new,
)

NAME = 'vpn-xray-tls-frontends'
UNIT = NAME + '.service'
LABEL = 'org.vpn-infra.role=' + NAME
PORTS = {env_port('VPN_STANDARD_TLS_PORT'): env_port('VPN_VLESS_AUTH_PORT'), env_port('VPN_PRIMARY_TLS_PORT'): env_port('VPN_PRIMARY_VLESS_PORT'), env_port('VPN_NL_RELAY_TLS_PORT'): env_port('VPN_NL_RELAY_VLESS_PORT'), env_port('VPN_THIRD_TLS_PORT'): env_port('VPN_THIRD_VLESS_PORT')}
SOURCE = env_value('VPN_LOOPBACK_IP')
CONFIG = Path('/etc') / NAME
RUNTIME = Path('/opt') / NAME
APPLICATION = RUNTIME / 'install_xray_tls_frontends.py'
SHARED_HELPER = RUNTIME / 'install_auto_tls_frontend.py'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
CIDFILE = Path('/run') / NAME / 'container.cid'
ENV_NAMES = ('VPN_STANDARD_TLS_PORT', 'VPN_PRIMARY_TLS_PORT', 'VPN_PRIMARY_VLESS_PORT',
             'VPN_NL_RELAY_TLS_PORT', 'VPN_NL_RELAY_VLESS_PORT',
             'VPN_THIRD_TLS_PORT', 'VPN_THIRD_VLESS_PORT')


def nginx_config(load_module='', *, ports=None, certificate=CERT_IN_CONTAINER):
    servers = []
    for public, backend in (PORTS if ports is None else ports).items():
        servers.append(env_expand(f'    server {{\n        listen ${{VPN_BIND_IP}}:{public} ssl;\n        proxy_pass ${{VPN_LOOPBACK_IP}}:{backend};\n        proxy_bind {SOURCE};\n    }}'))
    return f"""{load_module}worker_processes 1;
pid /tmp/nginx.pid;
lock_file /tmp/vpn-xray-nginx.lock;
error_log /dev/null crit;
events {{ worker_connections 2048; }}
stream {{
    access_log off;
    limit_conn_zone $server_port zone=xray_tls_sessions:1m;
    map $ssl_server_name $vpn_certificate {{
        default {certificate};
    }}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_handshake_timeout 8s;
    ssl_certificate $vpn_certificate;
    ssl_certificate_key $vpn_certificate;
    ssl_certificate_cache max=2 inactive=1m valid=30s;
    ssl_session_cache shared:xray_tls_session_cache:1m;
    ssl_session_tickets off;
    limit_conn xray_tls_sessions 256;
    proxy_connect_timeout 3s;
    proxy_timeout 15m;
    proxy_socket_keepalive on;
    proxy_half_close on;
{chr(10).join(servers)}
}}
"""


def container_args(uid, gid):
    return [
        '--pull=never', '--network=host', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user', f'{uid}:{gid}',
        '--memory=128m', '--cpus=0.5', '--pids-limit=24',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777',
        '--mount', f'type=bind,source={CONFIG / "nginx.conf"},target=/etc/nginx/nginx.conf,readonly',
        '--mount', f'type=bind,source={CERT_DIRECTORY},target=/etc/vpn-subscription,readonly',
        '--entrypoint', '/usr/sbin/nginx', IMAGE,
    ]


def unit_text(uid, gid):
    return f"""[Unit]
Description=Trusted TLS for existing Xray VLESS entries
Requires=docker.service
Wants=network-online.target
After=docker.service network-online.target x-ui.service vpn-balancer.service
[Service]
Type=simple
RuntimeDirectory={NAME}
RuntimeDirectoryMode=0700
ExecStart={DOCKER} {DOCKER_HOST} run --rm --name {NAME} --cidfile {CIDFILE} --label {LABEL} --log-driver=none {' '.join(container_args(uid, gid))} -e /dev/null -g "daemon off;"
ExecStop=/usr/bin/python3 -B {APPLICATION} stop-container
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def validate_backends(config):
    rules = config['routing']['rules']
    require(not config['routing'].get('script'), 'Main routing uses a script; wrapper preflight refused')
    for backend in PORTS.values():
        tag = f'in-{backend}-tcp'
        matching = [i for i in config['inbounds'] if i.get('tag') == tag]
        require(len(matching) == 1, 'A required main VLESS inbound is missing')
        inbound = matching[0]
        stream = inbound.get('streamSettings', {})
        transport = stream.get('rawSettings') or stream.get('tcpSettings') or {}
        require(inbound.get('protocol') == 'vless' and inbound.get('port') == backend
                and inbound.get('settings', {}).get('decryption') == 'none'
                and inbound.get('listen') in ('', env_value('VPN_LOOPBACK_IP'), env_value('VPN_BIND_IP'), env_value('VPN_BIND_IPV6_IP'))
                and stream.get('network') in ('raw', 'tcp') and stream.get('security', 'none') == 'none'
                and transport.get('header', {}).get('type', 'none') == 'none'
                and not transport.get('acceptProxyProtocol')
                and not stream.get('sockopt', {}).get('acceptProxyProtocol')
                and all(not c.get('flow') for c in inbound['settings'].get('clients', [])),
                'A backend does not accept unmodified plain VLESS')
        routes = [r for r in rules if r.get('inboundTag') == [tag]
                  and set(r) <= {'type', 'inboundTag', 'outboundTag'}]
        require(len(routes) == 1 and routes[0].get('outboundTag'), 'A backend has no unique existing catchall route')
    require(next(r['outboundTag'] for r in rules if r.get('inboundTag') == [env_expand('in-${VPN_VLESS_AUTH_PORT}-tcp')]
                 and set(r) <= {'type', 'inboundTag', 'outboundTag'}) == 'vpn-egress-pool',
            'The standard entry no longer uses the legacy pool')
    return [(r.get('outboundTag', ''), r.get('ruleTag', '')) for r in rules]


def check_backends():
    expected = validate_backends(json.loads(MAIN_CONFIG.read_bytes()))
    live = json.loads(command(str(MAIN_XRAY), 'api', 'lsrules', env_expand('--server=${VPN_LOOPBACK_IP}:${VPN_XUI_API_PORT}')))
    require([(r.get('tag', ''), r.get('ruleTag', '')) for r in live['rules']] == expected,
            'Live main routing differs from its saved configuration')
    for backend in PORTS.values():
        try:
            with socket.create_connection((env_value('VPN_LOOPBACK_IP'), backend), timeout=2, source_address=(SOURCE, 0)):
                pass
        except OSError:
            raise RuntimeError('An existing VLESS backend is unreachable on loopback') from None


def verify_listeners():
    trust = ssl.create_default_context()
    for port in PORTS:
        for _ in range(24):
            try:
                with socket.create_connection((env_value('VPN_LOOPBACK_IP'), port), timeout=1.5) as raw:
                    with trust.wrap_socket(raw, server_hostname=ADDRESS):
                        break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError('A new VLESS TLS entry did not answer with a trusted IP certificate')


def inspect_owned(cid):
    require(re.fullmatch(r'[a-f0-9]{64}', cid), 'Unexpected TLS frontend container ID')
    result = subprocess.run([DOCKER, DOCKER_HOST, 'container', 'inspect',
                             '--format', '{{json .Config.Labels}} {{.State.Running}}', cid],
                            capture_output=True, timeout=8)
    if result.returncode:
        return None
    labels, running = result.stdout.decode().strip().rsplit(' ', 1)
    require(json.loads(labels).get('org.vpn-infra.role') == NAME, 'Unexpected TLS frontend container owner')
    return running == 'true'


def stop_container():
    if CIDFILE.exists():
        cid = CIDFILE.read_text().strip()
        if inspect_owned(cid):
            command(DOCKER, DOCKER_HOST, 'stop', '--signal=SIGQUIT', '--time=18', cid)


def install():
    uid, gid = certificate_account()
    validate_certificate()
    check_backends()
    command(DOCKER, DOCKER_HOST, 'image', 'inspect', IMAGE)
    version = command(DOCKER, DOCKER_HOST, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                      '--cap-drop=ALL', '--user', f'{uid}:{gid}', '--entrypoint', '/usr/sbin/nginx', IMAGE,
                      '-V', include_stderr=True).decode()
    helper = Path(__file__).resolve().with_name('install_auto_tls_frontend.py')
    frozen = {CONFIG / 'nginx.conf': (nginx_config(stream_module(version)).encode(), 0o644),
              UNIT_PATH: (unit_text(uid, gid).encode(), 0o644)}
    helpers = {APPLICATION: (Path(__file__).read_bytes(), 0o600),
               SHARED_HELPER: (helper.read_bytes(), 0o600), **environment_payload(RUNTIME, ENV_NAMES)}
    payload = {**frozen, **helpers}
    paths = [CONFIG, RUNTIME, *payload]
    if any(os.path.lexists(p) for p in paths):
        require(APPLICATION.is_file() and SHARED_HELPER.is_file(), 'Existing TLS frontend helpers are missing')
        changed = refresh_runtime_helpers(RUNTIME, CONFIG, frozen, helpers,
                                          lambda: running_identity(UNIT, CIDFILE, NAME), verify_listeners)
        print(UNIT + (' private helpers refreshed; service unchanged' if changed else ' already active; no changes applied'))
        return
    require(command('systemctl', 'show', '--property=LoadState', '--value', UNIT).strip() == b'not-found',
            'The TLS frontend service name is already in use')
    names = command(DOCKER, DOCKER_HOST, 'container', 'ls', '-a', '--format', '{{.Names}}').decode().splitlines()
    require(NAME not in names, 'The TLS frontend container name is already in use')
    with_ports = []
    try:
        for port in PORTS:
            sock = socket.socket()
            with_ports.append(sock)
            sock.bind((env_value('VPN_BIND_IP'), port))
    finally:
        for sock in with_ports:
            sock.close()
    created = []
    started = reloaded = False
    try:
        for folder in (CONFIG, RUNTIME):
            folder.mkdir(mode=0o700)
            created.append(folder)
        for path, (data, mode) in payload.items():
            write_new(path, data, mode)
            created.append(path)
        command(DOCKER, DOCKER_HOST, 'run', '--rm', *container_args(uid, gid), '-e', '/dev/null', '-t')
        command('systemctl', 'daemon-reload')
        reloaded = True
        started = True
        command('systemctl', 'enable', '--now', UNIT)
        verify_listeners()
        command('systemctl', 'is-active', '--quiet', UNIT)
        require(CIDFILE.is_file() and inspect_owned(CIDFILE.read_text().strip()), 'TLS container is not running')
    except BaseException:
        if started:
            command('systemctl', 'disable', '--now', UNIT)
        for path in reversed(created):
            shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True)
        if reloaded:
            command('systemctl', 'daemon-reload')
        raise
    print(UNIT + ' started on ' + ','.join(map(str, PORTS)) + '; old VPN services were not restarted')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'stop-container'))
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Run as root on the Linux entry server')
        install() if args.action == 'install' else stop_container()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        parser.exit(1, 'install-xray-tls: ' + detail + '\n')


if __name__ == '__main__':
    main()
