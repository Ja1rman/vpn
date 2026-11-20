#!/usr/bin/env python3
"""Prepare fresh reserve credentials and add independent NL Telegram backends."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import shlex
import shutil
import subprocess
import tempfile
from urllib.parse import urlencode

import install_telegram_reserve as installer
from vpn_env import env, port


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/telegram-reserve/nl'
HELPERS = ('install_telegram_reserve.py', 'install_mtproto.py', 'install_mtproto_dd.py')


def private_write(path, body):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(body)


def prepare(folder=PRIVATE):
    folder = Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder.chmod(0o700)
    path = folder / 'credentials.json'
    protected = os.environ.get('VPN_TELEGRAM_RESERVE_CREDENTIALS_JSON')
    restored = None
    if protected:
        try:
            restored = json.loads(protected)
        except (ValueError, TypeError):
            raise RuntimeError('Protected reserve credentials must be valid JSON') from None
        # Validate protected input using exactly the private-file installer contract.
        with tempfile.TemporaryDirectory(prefix='reserve-restore-', dir=folder) as temporary:
            candidate = Path(temporary) / 'credentials.json'
            private_write(candidate, (json.dumps(restored) + '\n').encode())
            restored = installer.read_credentials(candidate)
    if path.exists() and restored is not None and installer.read_credentials(path) != restored:
        raise RuntimeError('Protected reserve credentials differ from existing keys; refusing rotation')
    if not path.exists():
        value = restored or {'scope': 'netherlands-reserve-fresh', 'username': 'reserve_' + secrets.token_hex(8),
                            'password': secrets.token_urlsafe(36), 'dd_key': secrets.token_hex(16),
                            'ee_key': secrets.token_hex(16), 'domain': 'yandex.ru'}
        private_write(path, (json.dumps(value, indent=2) + '\n').encode())
    value = installer.read_credentials(path)
    settings = installer.endpoints()
    for role in installer.ROLES:
        public = {'server': settings.public, 'port': port('VPN_NL_TELEGRAM_PUBLIC_PORT')}
        backend = {'server': settings.loopback, 'port': getattr(settings, role)}
        authentication = ({'username': value['username'], 'password': value['password']} if role == 'socks'
                          else {'secret': 'dd' + value['dd_key']} if role == 'dd'
                          else {'secret': 'ee' + value['ee_key'] + value['domain'].encode('ascii').hex()})
        for name, document in (('access.json', public), ('backend-access.json', backend)):
            document.update(authentication)
            destination = folder / role / name
            encoded = (json.dumps(document, indent=2) + '\n').encode()
            if destination.exists():
                if destination.is_symlink() or destination.read_bytes() != encoded:
                    raise RuntimeError('Different reserve access artifacts already exist; inspect them privately')
            else:
                private_write(destination, encoded)
        link_authentication = ({'user': value['username'], 'pass': value['password']}
                               if role == 'socks' else authentication)
        link = ('tg://' + ('socks' if role == 'socks' else 'proxy') + '?'
                + urlencode({'server': settings.public, 'port': public['port']} | link_authentication))
        text = ('# Netherlands reserve ' + role.upper() + '\n\n'
                'Public link becomes available after the separately verified ingress classifier deployment.\n\n'
                + link + '\n')
        destination = folder / role / 'access.md'
        if not destination.exists():
            private_write(destination, text.encode())
    return path


def refresh_public_port(folder=PRIVATE):
    """CAS-migrate unpublished access metadata, preserving credentials and backend files."""
    folder = Path(folder)
    installer.read_credentials(folder / 'credentials.json')
    previous, current = port('VPN_NL_RELAY_TLS_PORT'), port('VPN_NL_TELEGRAM_PUBLIC_PORT')
    before, after = {}, {}
    for role in installer.ROLES:
        path = folder / role / 'access.json'
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_mode & 0o077:
            raise RuntimeError('Public reserve metadata must be a private regular file')
        raw = path.read_bytes()
        value = json.loads(raw)
        if value.get('server') != env('VPN_NL_ADDRESS') or value.get('port') not in (previous, current):
            raise RuntimeError('Unexpected public reserve endpoint; refusing metadata update')
        if value['port'] == current:
            continue
        before[path] = raw
        value['port'] = current
        after[path] = (json.dumps(value, indent=2) + '\n').encode()
        document = path.with_name('access.md')
        info = document.lstat()
        if not document.is_file() or document.is_symlink() or info.st_mode & 0o077:
            raise RuntimeError('Public reserve documentation must be a private regular file')
        before[document] = document.read_bytes()
        pattern = r'([?&]port=)' + re.escape(str(previous)) + r'(?=&|\s|$)'
        changed, count = re.subn(pattern, lambda match: match[1] + str(current),
                                 before[document].decode())
        if count != 1:
            raise RuntimeError('Unexpected public reserve link; refusing metadata update')
        after[document] = changed.encode()
    if not before:
        return {'already_current': True, 'credentials_changed': False}
    backup = folder / ('public-access-before-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(mode=0o700)
    for path, data in before.items():
        private_write(backup / path.relative_to(folder), data)
    if any(path.read_bytes() != data for path, data in before.items()):
        raise RuntimeError('Reserve metadata changed concurrently; no update applied')
    written = []
    try:
        for path, data in after.items():
            if path.read_bytes() != before[path]:
                raise RuntimeError('Reserve metadata changed concurrently')
            temporary = path.with_name('.access-update-' + secrets.token_hex(8))
            try:
                private_write(temporary, data)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
            written.append(path)
    except BaseException:
        if any(path.read_bytes() != after[path] for path in written):
            raise RuntimeError('Updated metadata changed concurrently; private backup preserved') from None
        for path in reversed(written):
            temporary = path.with_name('.access-restore-' + secrets.token_hex(8))
            private_write(temporary, before[path])
            os.replace(temporary, path)
        raise
    return {'updated_files': len(written), 'credentials_changed': False, 'backup': str(backup)}


def build_probe():
    output = ROOT / '.local/telegram-probe/telegram-probe-linux-amd64'
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOMAXPROCS='2',
                       GOCACHE=str(ROOT / '.local/telegram-probe/build-cache'),
                       GOMODCACHE=str(ROOT / '.local/telegram-probe/modules'))
    result = subprocess.run(['go', 'build', '-mod=readonly', '-p', '2', '-trimpath', '-o', str(output), '.'],
                            cwd=ROOT / 'tools/telegram-probe', env=environment, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError('Pinned anonymous Telegram client build failed')
    return output


SNAPSHOT = r'''import hashlib,json,sqlite3
from pathlib import Path
value={'pids':{},'files':{}}
for item in Path('/proc').iterdir():
 if item.name.isdigit():
  try:
   name=(item/'comm').read_text().strip()
   if name in ('xray-linux-amd6','xray','x-ui'):value['pids'][item.name]=name
  except (OSError,ProcessLookupError):pass
for name in ('/usr/local/x-ui/bin/config.json',):
 path=Path(name)
 if path.is_file():value['files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
database=Path('/etc/x-ui/x-ui.db')
if database.is_file():
 with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as connection:
  columns={row[1] for row in connection.execute('PRAGMA table_info(inbounds)')}
  selected=[name for name in ('id','enable','port','protocol','settings','stream_settings','sniffing') if name in columns]
  rows=connection.execute('SELECT '+','.join(selected)+' FROM inbounds ORDER BY id').fetchall()
  value['files']['x-ui-inbound-configuration']=hashlib.sha256(json.dumps(rows).encode()).hexdigest()
print(json.dumps(value,sort_keys=True))
'''


def deploy(*, controller=None, folder=PRIVATE):
    if controller is None:
        import vpnctl as controller
    credentials = prepare(folder)
    probe = build_probe()
    name = 'breeze-reef'
    settings = installer.endpoints()
    before = controller.remote(name, 'sudo python3 -', SNAPSHOT.encode(), capture=True).stdout
    assets = {'sing.tar.gz': ROOT / '.local/compatible-vless' / installer.SING_ARCHIVE_NAME,
              'ee.tar.gz': ROOT / '.local/mtproto' / installer.ee.ARCHIVE_NAME,
              'dd.tar.gz': ROOT / '.local/mtproto-dd/assets/source.tar.gz',
              'pysocks.whl': ROOT / '.local/mtproto-dd/assets/PySocks-1.7.1-py3-none-any.whl'}
    # Validate pins and credentials locally before uploading any new reserve material.
    installer.payload(assets['sing.tar.gz'], assets['ee.tar.gz'], assets['dd.tar.gz'],
                      assets['pysocks.whl'], installer.read_credentials(credentials), settings)
    with tempfile.TemporaryDirectory(prefix='telegram-reserve-', dir=ROOT / '.local') as temporary:
        staging = Path(temporary)
        for filename, source in assets.items():
            shutil.copyfile(source, staging / filename)
        shutil.copyfile(credentials, staging / 'credentials.json')
        (staging / 'credentials.json').chmod(0o600)
        shutil.copyfile(probe, staging / 'telegram-probe')
        for role in installer.ROLES:
            shutil.copyfile(Path(folder) / role / 'backend-access.json', staging / (role + '.json'))
            (staging / (role + '.json')).chmod(0o600)
        stage = controller.upload(name, staging, HELPERS)
        try:
            result = controller.remote(name, 'sudo ' + shlex.join([
                'python3', '-B', stage + '/install_telegram_reserve.py',
                '--sing-archive', stage + '/payload/sing.tar.gz',
                '--ee-archive', stage + '/payload/ee.tar.gz',
                '--dd-archive', stage + '/payload/dd.tar.gz',
                '--socks-wheel', stage + '/payload/pysocks.whl',
                '--credentials', stage + '/payload/credentials.json']), capture=True)
            installation = json.loads(result.stdout)
            controller.remote(name, 'sudo chmod 700 ' + shlex.quote(stage + '/payload/telegram-probe'))

            def verify(role):
                command = 'sudo ' + shlex.join([stage + '/payload/telegram-probe',
                           '--mode', 'socks' if role == 'socks' else 'mtproto',
                           '--access', stage + '/payload/' + role + '.json', '--dc', '2'])
                result = controller.remote(name, command, capture=True)
                row = json.loads(result.stdout)
                if (row.get('status') != 'passed' or row.get('account_login') is not False
                        or row.get('rpc') != 'help.getNearestDC'):
                    raise RuntimeError('A reserve anonymous native Telegram proof failed')
                return role, row

            with ThreadPoolExecutor(max_workers=len(installer.ROLES)) as executor:
                proof = dict(executor.map(verify, installer.ROLES))
            after = controller.remote(name, 'sudo python3 -', SNAPSHOT.encode(), capture=True).stdout
            unchanged = json.loads(before) == json.loads(after)
            if not unchanged:
                raise RuntimeError('Existing VPN PID or configuration baseline changed; inspect privately')
            report = {'installation': installation, 'native_clients': proof,
                      'old_vpn_baseline_unchanged': unchanged, 'direct_exit': True,
                      'loopback_only': True, 'public_ingress_deployed': False}
            destination = Path(folder) / 'deployment-report.json'
            if destination.exists():
                destination.unlink()
            private_write(destination, (json.dumps(report, indent=2) + '\n').encode())
            return report
        finally:
            controller.remote(name, 'sudo rm -rf -- ' + shlex.quote(stage))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--refresh-public-port', action='store_true')
    args = parser.parse_args()
    if args.refresh_public_port:
        print(json.dumps(refresh_public_port(), sort_keys=True))
    elif args.prepare_only:
        prepare()
        print(json.dumps({'prepared': True, 'private_directory': str(PRIVATE)}))
    else:
        try:
            print(json.dumps(deploy(), sort_keys=True))
        except subprocess.CalledProcessError:
            raise SystemExit('A reserve deployment or anonymous native proof failed; private staging was cleaned') from None


if __name__ == '__main__':
    main()
