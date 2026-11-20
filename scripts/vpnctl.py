#!/usr/bin/env python3
"""SSH deployment helper. Uses host key verification; never modifies back."""
import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
from vpn_env import configured_values, env, expand, load_json, port
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json

ROOT=Path(__file__).resolve().parents[1]
INVENTORY=ROOT/'inventory/hosts.json'

def inventory():return load_json(INVENTORY)

def node(name):
    inv=inventory()
    standalone=[n for n in inv.get('failover',{}).get('egresses',[]) if n.get('source')=='file' and 'user' in n]
    return next(n for n in [inv['entry']]+inv['nodes']+standalone if n['name']==name)

def ssh_args(name):
    n=node(name)
    args=['ssh','-o',f'UserKnownHostsFile={ROOT}/.local/ssh/known_hosts','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=4','-o','ControlMaster=auto','-o',f'ControlPath={ROOT}/.local/ssh/%C','-o','ControlPersist=600',f'{n["user"]}@{n["address"]}']
    password=ROOT/'.local/ssh'/f'{name}.password'
    # Legacy local filename retained for the initial Netherlands credential.
    if name=='breeze-reef' and not password.exists():password=ROOT/'.local/ssh/nl.password'
    if password.exists():args=['sshpass','-f',str(password)]+args
    return args

def remote(name,command,data=None,capture=False):
    return subprocess.run(ssh_args(name)+[command],input=data,check=True,stdout=subprocess.PIPE if capture else None)

def upload(name,folder,extras=()):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as archive:
        archive.add(folder,arcname='payload')
        for filename in extras:archive.add(ROOT/'scripts'/filename,arcname=filename)
        archive.add(ROOT/'scripts/vpn_env.py', arcname='vpn_env.py')
        environment = json.dumps(configured_values()).encode()
        info = tarfile.TarInfo('vpn.env.json')
        info.size, info.mode = len(environment), 0o600
        archive.addfile(info, io.BytesIO(environment))
    stage='/opt/vpn-infra/staging/'+name+'/'+folder.name
    remote(name,f'sudo install -d -m 700 {stage} && sudo tar xzf - -C {stage}',stream.getvalue())
    return stage

def backup(name):
    output=ROOT/'.local/backups'/f'{name}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.tar.gz'
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('wb') as file:
        subprocess.run(ssh_args(name)+['sudo python3 -'],input=(ROOT/'scripts/backup_remote.py').read_bytes(),stdout=file,check=True)
    print(output)

def deploy_node(name):
    n=node(name); inv=inventory();release=json.loads((ROOT/'monitoring/releases.json').read_text())['node_exporter']
    stage=upload(name,ROOT/'.local/rendered/nodes'/name,['install_node.sh'])
    address=env_value('VPN_LOOPBACK_IP') if name==inv['entry']['name'] else env_value('VPN_BIND_IP')
    remote(name,'sudo bash '+shlex.join([stage+'/install_node.sh',stage+'/payload',f'{address}:{inv["monitoring"]["node_port"]}',release['version'],release['sha256_linux_amd64']]))

def deploy_monitoring():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring',['install_monitoring.sh','rename_grafana_user.py'])
    # Fresh installations have no existing account to migrate.
    remote(name,env_expand('if curl -fsS http://${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}/api/health >/dev/null 2>&1; then sudo python3 ')+shlex.join([stage+'/rename_grafana_user.py',stage+'/payload'])+'; fi')
    remote(name,'sudo bash '+shlex.join([stage+'/install_monitoring.sh',stage+'/payload']))

def refresh_grafana():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring',['refresh_grafana.sh','rename_grafana_user.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/rename_grafana_user.py',stage+'/payload']))
    remote(name,'sudo bash '+shlex.join([stage+'/refresh_grafana.sh',stage+'/payload']))

def deploy_grafana_https():
    import shutil
    import tempfile

    entry = inventory()['entry']
    template = ROOT / 'monitoring/nginx-grafana-https.conf'
    with tempfile.TemporaryDirectory(prefix='grafana-https-', dir=ROOT / '.local') as tmp:
        folder = Path(tmp)
        shutil.copyfile(template, folder / template.name)
        stage = upload(entry['name'], folder, ['install_grafana_https.py'])
        try:
            remote(entry['name'], 'sudo python3 ' + shlex.join([
                stage + '/install_grafana_https.py', 'install', stage + '/payload/' + template.name,
                '--address', entry['address'],
            ]))
        finally:
            remote(entry['name'], 'sudo rm -rf -- ' + shlex.quote(stage))

def deploy_vpn_usage():
    import shutil
    import tempfile

    name = inventory()['entry']['name']
    private = ROOT / '.local'
    with tempfile.TemporaryDirectory(prefix='vpn-usage-', dir=private) as tmp:
        folder = Path(tmp)
        monitoring = ROOT / 'monitoring'
        for unit in ('vpn-usage-collector.service', 'vpn-usage-collector.timer'):
            shutil.copyfile(monitoring / 'usage' / unit, folder / unit)
        shutil.copyfile(monitoring / 'grafana/dashboards/vpn-usage.json', folder / 'vpn-usage.json')
        mapping = private / 'vpn-usage-devices.json'
        if mapping.is_file():
            shutil.copyfile(mapping, folder / 'devices.json')
        stage = upload(name, folder, ['install_vpn_usage.sh', 'vpn_usage_collector.py'])
        try:
            remote(name, 'sudo bash ' + shlex.join([stage + '/install_vpn_usage.sh', stage]))
        finally:
            remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))

def refresh_alertmanager():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/monitoring/alertmanager',['refresh_alertmanager.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/refresh_alertmanager.py',stage+'/payload/alertmanager.yml']))

def deploy_balancer():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/balancer',['install_balancer.sh'])
    remote(name,'sudo bash '+shlex.join([stage+'/install_balancer.sh',stage+'/payload']))

def activate_balancer():
    name=inventory()['entry']['name']
    folder=ROOT/'.local/activation';folder.mkdir(exist_ok=True)
    stage=upload(name,folder,['panel.py','activate_balancer.py'])
    remote(name,'sudo python3 '+shlex.quote(stage+'/activate_balancer.py'))

def migrate_direct_inbounds():
    name=inventory()['entry']['name']
    folder=ROOT/'.local/route-migration';folder.mkdir(exist_ok=True)
    stage=upload(name,folder,['panel.py','activate_balancer.py','verify_vpn.py','migrate_direct_inbounds.py'])
    remote(name,'sudo python3 '+shlex.quote(stage+'/migrate_direct_inbounds.py'))

def update_pool():
    name=inventory()['entry']['name']
    stage=upload(name,ROOT/'.local/rendered/balancer',['update_pool.py','verify_vpn.py'])
    remote(name,'sudo python3 '+shlex.join([stage+'/update_pool.py',stage+'/payload/config.json']))

def deploy_compatible():
    from compatible_vless import VERSION, ARCHIVE_SHA256
    import hashlib
    import shutil
    archive=ROOT/'.local/compatible-vless'/f'sing-box-{VERSION}-linux-amd64.tar.gz'
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest()!=ARCHIVE_SHA256:
        raise RuntimeError('Place the pinned official sing-box archive in .local/compatible-vless first')
    folder=ROOT/'.local/rendered/compatible-vless-bootstrap'
    folder.mkdir(parents=True,mode=0o700,exist_ok=True)
    shutil.copyfile(archive,folder/archive.name)
    stage=upload(inventory()['entry']['name'],folder,['compatible_vless.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/compatible_vless.py','install','--archive',stage+'/payload/'+archive.name]))

def publish_compatible():
    folder=ROOT/'.local/compatible-publication';folder.mkdir(mode=0o700,exist_ok=True)
    stage=upload(inventory()['entry']['name'],folder,['compatible_profiles.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/compatible_profiles.py','publish','--address',inventory()['entry']['address']]))

def refresh_probes():
    stage=upload(inventory()['entry']['name'],ROOT/'.local/rendered/monitoring/prometheus',['refresh_probe_targets.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/refresh_probe_targets.py',stage+'/payload/vpn-targets.json']))

def stage_failover():
    from failover_variant import private_outbound_file
    import tempfile
    raw=INVENTORY.read_bytes()
    inv=load_json(INVENTORY)
    with tempfile.TemporaryDirectory(prefix='failover-deploy-',dir=ROOT/'.local') as tmp:
        folder=Path(tmp)
        (folder/'hosts.json').write_bytes(raw)
        for entry in inv['failover']['egresses']:
            if entry['source']=='file':
                filename=private_outbound_file(entry)
                source=ROOT/'.local/outbounds'/filename
                if source.is_symlink() or not source.is_file():
                    raise ValueError('Missing private outbound: '+filename)
                (folder/'outbounds').mkdir(mode=0o700,exist_ok=True)
                (folder/'outbounds'/filename).write_bytes(source.read_bytes())
        return upload(inv['entry']['name'],folder,[
            'failover_variant.py','priority_pool.py','verify_priority_backup.py','verify_vpn.py',
            'enable_failover_variant.py','failover_subscription.py','install_failover_subscription.py',
            'update_failover_pool.py','auto_ru_routes.py','enable_auto_ru.py','telegram_local_routes.py'])

def update_failover_pool():
    stage=stage_failover()
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/update_failover_pool.py',stage+'/payload/hosts.json']))

def deploy_auto_onboarding():
    import tempfile

    name = inventory()['entry']['name']
    with tempfile.TemporaryDirectory(prefix='auto-onboarding-', dir=ROOT / '.local') as tmp:
        stage = upload(name, Path(tmp), ['install_auto_tls_frontend.py', 'verify_auto_onboarding.py',
                                         'install_failover_subscription.py', 'failover_subscription.py',
                                         'install_telegram_forwarders.py'])
        try:
            actions = [
                ['python3', '-B', f'{stage}/install_auto_tls_frontend.py', 'install'],
                ['python3', '-B', f'{stage}/install_telegram_forwarders.py', 'install', '--component', 'auto'],
                ['python3', '-B', f'{stage}/verify_auto_onboarding.py'],
                ['python3', '-B', f'{stage}/install_failover_subscription.py', 'upgrade', '--allow-profile-update'],
            ]
            command = ' && '.join(shlex.join(action) for action in actions)
            remote(name, 'sudo ' + shlex.join([
                'flock', '-n', '/run/lock/vpn-auto-onboarding.lock', 'bash', '-c', command,
            ]))
        finally:
            remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))

def deploy_xray_subscriptions():
    import tempfile

    name = inventory()['entry']['name']
    helpers = ['install_xray_tls_frontends.py', 'install_auto_tls_frontend.py',
               'install_telegram_forwarders.py',
               'xray_subscription_hosts.py', 'verify_xray_subscriptions.py',
               'verify_xray_vless.py', 'compatible_vless.py', 'compatible_profiles.py',
               'verify_auto_onboarding.py', 'failover_subscription.py', 'install_failover_subscription.py']
    with tempfile.TemporaryDirectory(prefix='xray-subscriptions-', dir=ROOT / '.local') as tmp:
        stage = upload(name, Path(tmp), helpers)
        try:
            script = '''import ipaddress, json, subprocess, sys
from pathlib import Path
stage = Path(sys.argv[1])
sys.path.insert(0, str(stage))
import install_xray_tls_frontends as frontend
import install_failover_subscription as subscription
import xray_subscription_hosts as hosts

def check(name, *arguments):
    subprocess.run([sys.executable, '-B', str(stage / name), *arguments], check=True, timeout=180)

frontend.install()
check('install_auto_tls_frontend.py', 'install')
check('install_telegram_forwarders.py', 'install', '--component', 'auto')
check('verify_xray_subscriptions.py', '--candidate-tls')
print(json.dumps(subscription.upgrade(stage / 'failover_subscription.py', allow_profile_update=True)), flush=True)
published = hosts.apply(hosts.DATABASE, ipaddress.IPv4Address(frontend.ADDRESS), hosts.BACKUPS)
print(json.dumps(published), flush=True)
try:
    check('verify_xray_subscriptions.py')
    check('verify_auto_onboarding.py')
except BaseException:
    if published['backup']:
        print(json.dumps(hosts.rollback(hosts.DATABASE, Path(published['backup']))), flush=True)
    raise
'''
            remote(name, 'sudo ' + shlex.join([
                'flock', '-n', '/run/lock/vpn-auto-onboarding.lock', 'python3', '-B', '-', stage,
            ]), script.encode())
        finally:
            remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))

def deploy_mtproto():
    import hashlib
    import re
    import secrets
    import shutil
    import tempfile
    import urllib.parse
    import urllib.request
    from install_mtproto import ARCHIVE_NAME, ARCHIVE_SHA256, PORT, VERSION

    entry = inventory()['entry']
    private = ROOT / '.local/mtproto'
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    access_file = private / 'access.json'
    previous = json.loads(access_file.read_text()) if access_file.exists() else {}
    secret = os.environ.get('VPN_MTPROTO_SECRET') or previous.get('secret')
    if not secret:
        secret = 'ee' + secrets.token_hex(16) + 'yandex.ru'.encode().hex()
    if not isinstance(secret, str):
        raise ValueError('VPN_MTPROTO_SECRET must be a hexadecimal FakeTLS secret')
    secret = secret.strip().lower()
    if not re.fullmatch(r'ee[0-9a-f]+', secret):
        raise ValueError('Invalid hexadecimal FakeTLS secret')
    try:
        raw = bytes.fromhex(secret)
        domain = raw[17:].decode('ascii')
    except (ValueError, UnicodeError):
        raise ValueError('Invalid hexadecimal FakeTLS secret') from None
    if (len(raw) <= 17 or len(domain) > 253
            or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                                r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain)):
        raise ValueError('The FakeTLS secret must contain a valid cover domain')
    fields = {'server': entry['address'], 'port': env_port('VPN_MTPROTO_PUBLIC_PORT'), 'secret': secret}
    query = urllib.parse.urlencode(fields)
    access = dict(fields, domain=domain, tg_url='tg://proxy?' + query, web_url='https://t.me/proxy?' + query)
    access_file.write_text(json.dumps(access, indent=2) + '\n')
    access_file.chmod(0o600)
    archive = private / ARCHIVE_NAME
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        url = f'https://github.com/9seconds/mtg/releases/download/v{VERSION}/{ARCHIVE_NAME}'
        with tempfile.NamedTemporaryFile(dir=private, delete=False) as temporary:
            candidate = Path(temporary.name)
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    shutil.copyfileobj(response, temporary)
                temporary.flush()
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != ARCHIVE_SHA256:
                    raise ValueError('The official mtg archive failed checksum verification')
                candidate.replace(archive)
            finally:
                candidate.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='mtproto-', dir=ROOT / '.local') as tmp:
        folder = Path(tmp)
        shutil.copyfile(archive, folder / ARCHIVE_NAME)
        shutil.copyfile(access_file, folder / 'access.json')
        stage = upload(entry['name'], folder, ['install_mtproto.py', 'verify_mtproto.py'])
        try:
            actions = [
                ['python3', '-B', stage + '/install_mtproto.py', 'install',
                 '--archive', stage + '/payload/' + ARCHIVE_NAME,
                 '--secrets-file', stage + '/payload/access.json'],
                ['python3', '-B', stage + '/verify_mtproto.py', '--host', env_value('VPN_LOOPBACK_IP'), '--port', str(PORT),
                 '--config', '/etc/vpn-mtproto/config.toml', '--dc', '2'],
            ]
            remote(entry['name'], 'sudo ' + shlex.join([
                'flock', '-n', '/run/lock/vpn-mtproto.lock', 'bash', '-c',
                ' && '.join(shlex.join(action) for action in actions),
            ]))
            config = remote(entry['name'], 'sudo cat /etc/vpn-mtproto/config.toml', capture=True).stdout
            (private / 'config.toml').write_bytes(config)
            (private / 'config.toml').chmod(0o600)
        finally:
            remote(entry['name'], 'sudo rm -rf -- ' + shlex.quote(stage))
    (private / 'access.md').write_text(
        '# Telegram MTProto\n\n' + f"[Подключить Telegram]({access['web_url']})\n\n"
        + f"[Открыть в приложении]({access['tg_url']})\n\n"
        + f"Сервер `{entry['address']}`, порт `{access['port']}`, секрет `{secret}`.\n"
    )
    (private / 'access.md').chmod(0o600)
    deploy_telegram_socks()
    if configured_values().get('VPN_MTPROTO_DD_PORT'):
        deploy_mtproto_dd()
    print('MTProto installed and verified; connection links saved privately in .local/mtproto/access.md')


def deploy_mtproto_dd():
    import hashlib
    import shutil
    import tempfile
    import urllib.parse
    import urllib.request
    import install_mtproto_dd as installer
    from verify_mtproto import parse_secret

    entry = inventory()['entry']
    original = ROOT / '.local/mtproto/access.json'
    secret = os.environ.get('VPN_MTPROTO_SECRET')
    if not secret and original.exists():
        secret = json.loads(original.read_text())['secret']
    if not secret:
        raise ValueError('Set VPN_MTPROTO_SECRET or deploy the existing MTProto service first')
    key, _domain = parse_secret(secret)
    private = ROOT / '.local/mtproto-dd'
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    access_file = private / 'access.json'
    access = {'server': entry['address'], 'port': port('VPN_MTPROTO_DD_PORT'), 'secret': 'dd' + key.hex()}
    if access_file.exists() and json.loads(access_file.read_text()).get('secret') != access['secret']:
        raise ValueError('The existing DD client secret differs; refusing an implicit credential rotation')
    query = urllib.parse.urlencode(access)
    access.update(tg_url='tg://proxy?' + query, web_url='https://t.me/proxy?' + query)
    assets = private / 'assets'
    assets.mkdir(mode=0o700, exist_ok=True)
    inputs = [
        ('source.tar.gz', installer.SOURCE_URL, installer.ARCHIVE_SHA256),
        ('PySocks-1.7.1-py3-none-any.whl', installer.SOCKS_WHEEL_URL, installer.SOCKS_WHEEL_SHA256),
    ]
    for filename, url, digest in inputs:
        target = assets / filename
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        with tempfile.NamedTemporaryFile(dir=assets, delete=False) as temporary:
            candidate = Path(temporary.name)
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    shutil.copyfileobj(response, temporary)
                temporary.flush()
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                    raise ValueError('A pinned DD proxy deployment asset failed checksum verification')
                candidate.replace(target)
            finally:
                candidate.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='mtproto-dd-', dir=ROOT / '.local') as temporary:
        folder = Path(temporary)
        for filename, _url, _digest in inputs:
            shutil.copyfile(assets / filename, folder / filename)
        (folder / 'secrets.json').write_text(json.dumps({'secret': secret}))
        (folder / 'secrets.json').chmod(0o600)
        stage = upload(entry['name'], folder, ['install_mtproto_dd.py'])
        try:
            remote(entry['name'], 'sudo python3 -B ' + shlex.join([
                stage + '/install_mtproto_dd.py', 'install', '--archive', stage + '/payload/source.tar.gz',
                '--socks-wheel', stage + '/payload/PySocks-1.7.1-py3-none-any.whl',
                '--secrets-file', stage + '/payload/secrets.json']))
            config = remote(entry['name'], 'sudo cat /etc/vpn-mtproto-dd/config.py', capture=True).stdout
            (private / 'config.py').write_bytes(config)
            (private / 'config.py').chmod(0o600)
        finally:
            remote(entry['name'], 'sudo rm -rf -- ' + shlex.quote(stage))
    access_file.write_text(json.dumps(access, indent=2) + '\n')
    access_file.chmod(0o600)
    (private / 'access.md').write_text('# Telegram MTProto DD\n\n[Подключить](' + access['web_url'] + ')\n')
    (private / 'access.md').chmod(0o600)
    print('MTProto DD installed; connection links saved privately in .local/mtproto-dd/access.md')

def deploy_telegram_socks():
    import secrets
    import tempfile
    import urllib.parse

    entry = inventory()['entry']
    private = ROOT / '.local/telegram-socks'
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = private / 'access.json'
    access = json.loads(path.read_text()) if path.exists() else {}
    access['username'] = (os.environ.get('VPN_TELEGRAM_SOCKS_USERNAME') or access.get('username')
                          or 'tg_' + secrets.token_hex(4))
    access['password'] = (os.environ.get('VPN_TELEGRAM_SOCKS_PASSWORD') or access.get('password')
                          or secrets.token_urlsafe(30))
    access.update(server=entry['address'], port=env_port('VPN_TELEGRAM_SOCKS_PORT'))
    query = urllib.parse.urlencode({'server': access['server'], 'port': access['port'],
                                    'user': access['username'], 'pass': access['password']})
    access.update(web_url='https://t.me/socks?' + query, tg_url='tg://socks?' + query)
    path.write_text(json.dumps(access, indent=2) + '\n')
    path.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='telegram-socks-', dir=ROOT / '.local') as tmp:
        folder = Path(tmp)
        (folder / 'access.json').write_text(json.dumps(access))
        (folder / 'access.json').chmod(0o600)
        stage = upload(entry['name'], folder, ['install_telegram_socks.py', 'verify_mtproto.py'])
        try:
            remote(entry['name'], 'sudo python3 -B ' + shlex.join([
                stage + '/install_telegram_socks.py', 'install', '--secrets-file', stage + '/payload/access.json']))
            remote(entry['name'], 'sudo python3 -B ' + shlex.join([
                stage + '/verify_mtproto.py', '--host', env_value('VPN_LOOPBACK_IP'),
                '--port', str(env_port('VPN_MTPROTO_PUBLIC_PORT')), '--config', '/etc/vpn-mtproto/config.toml']))
            config = remote(entry['name'], 'sudo cat /etc/vpn-telegram-socks/config.json', capture=True).stdout
            (private / 'config.json').write_bytes(config)
            (private / 'config.json').chmod(0o600)
        finally:
            remote(entry['name'], 'sudo rm -rf -- ' + shlex.quote(stage))
    (private / 'access.md').write_text('# Telegram SOCKS5\n\n[Подключить](' + access['web_url'] + ')\n')
    (private / 'access.md').chmod(0o600)
    print('Telegram SOCKS5 credentials saved privately in .local/telegram-socks/access.md')

def deploy_web_proxy():
    from deploy_web_proxy import deploy
    print(json.dumps(deploy()))

def refresh_failover_monitoring():
    import shutil
    folder=ROOT/'.local/failover-monitoring'
    (folder/'prometheus').mkdir(parents=True,mode=0o700,exist_ok=True)
    for name in ('blackbox.yml','prometheus/prometheus.yml','prometheus/alerts.yml','prometheus/vpn-targets.json'):
        shutil.copyfile(ROOT/'.local/rendered/monitoring'/name,folder/name)
    stage=upload(inventory()['entry']['name'],folder,['refresh_failover_alerts.py'])
    remote(inventory()['entry']['name'],'sudo python3 '+shlex.join([
        stage+'/refresh_failover_alerts.py',stage+'/payload','--apply']))

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['backup','deploy-node','deploy-monitoring','refresh-grafana','deploy-grafana-https','deploy-vpn-usage','refresh-alertmanager','refresh-probes','deploy-balancer','activate-balancer','migrate-direct-inbounds','update-pool','update-failover-pool','deploy-compatible','publish-compatible','stage-failover','deploy-auto-onboarding','deploy-xray-subscriptions','deploy-mtproto','deploy-mtproto-dd','deploy-telegram-socks','deploy-telegram-reserve','deploy-web-proxy','deploy-telegram-local','refresh-failover-monitoring','ssh','tunnel'])
    parser.add_argument('name',nargs='?',default='entry')
    args=parser.parse_args()
    if args.command=='backup':backup(args.name)
    elif args.command=='deploy-node':deploy_node(args.name)
    elif args.command=='deploy-monitoring':deploy_monitoring()
    elif args.command=='refresh-grafana':refresh_grafana()
    elif args.command=='deploy-grafana-https':deploy_grafana_https()
    elif args.command=='deploy-vpn-usage':deploy_vpn_usage()
    elif args.command=='refresh-alertmanager':refresh_alertmanager()
    elif args.command=='deploy-balancer':deploy_balancer()
    elif args.command=='activate-balancer':activate_balancer()
    elif args.command=='migrate-direct-inbounds':migrate_direct_inbounds()
    elif args.command=='update-pool':update_pool()
    elif args.command=='deploy-compatible':deploy_compatible()
    elif args.command=='publish-compatible':publish_compatible()
    elif args.command=='refresh-probes':refresh_probes()
    elif args.command=='stage-failover':print(stage_failover())
    elif args.command=='update-failover-pool':update_failover_pool()
    elif args.command=='deploy-auto-onboarding':deploy_auto_onboarding()
    elif args.command=='deploy-xray-subscriptions':deploy_xray_subscriptions()
    elif args.command=='deploy-mtproto':deploy_mtproto()
    elif args.command=='deploy-mtproto-dd':deploy_mtproto_dd()
    elif args.command=='deploy-telegram-socks':deploy_telegram_socks()
    elif args.command=='deploy-telegram-reserve':subprocess.run([sys.executable, str(ROOT/'scripts/deploy_telegram_reserve.py')], check=True)
    elif args.command=='deploy-web-proxy':deploy_web_proxy()
    elif args.command=='deploy-telegram-local':subprocess.run([sys.executable, str(ROOT/'scripts/deploy_telegram_local.py')], check=True)
    elif args.command=='refresh-failover-monitoring':refresh_failover_monitoring()
    elif args.command=='ssh':subprocess.run(ssh_args(args.name),check=True)
    elif args.command=='tunnel':
        cmd=ssh_args(inventory()['entry']['name'])
        cmd[-1:-1]=['-N','-o','ExitOnForwardFailure=yes','-L',env_expand('${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}:${VPN_LOOPBACK_IP}:${VPN_GRAFANA_PORT}'),'-L',env_expand('${VPN_LOOPBACK_IP}:${VPN_PROMETHEUS_PORT}:${VPN_LOOPBACK_IP}:${VPN_PROMETHEUS_PORT}'),'-L',env_expand('${VPN_LOOPBACK_IP}:${VPN_ALERTMANAGER_PORT}:${VPN_LOOPBACK_IP}:${VPN_ALERTMANAGER_PORT}')]
        subprocess.run(cmd,check=True)

if __name__=='__main__':main()
