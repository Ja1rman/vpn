#!/usr/bin/env python3
"""Prepare or add only the official loopback WEB relay on the entry server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import stat
import tempfile
import urllib.request

import build_web_proxy as builder
import install_web_proxy as installer


def write_private(path, body):
    if os.path.lexists(path):
        installer.require(stat.S_ISREG(path.lstat().st_mode), 'Refusing a nonregular private WEB artifact')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(body)


def _dd_secret(path):
    info = path.lstat()
    installer.require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 65536,
                      'The existing DD access must be a private regular JSON file')
    return json.loads(path.read_text())['secret']


def prepare(controller=None):
    if controller is None:
        import vpnctl as controller
    settings = installer.endpoint_settings()
    private = controller.ROOT / '.local/web-proxy'
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials_file = private / 'credentials.json'
    supplied = os.environ.get('VPN_WEB_PROXY_CREDENTIALS_JSON')
    if supplied:
        with tempfile.NamedTemporaryFile(mode='w', dir=private) as temporary:
            temporary.write(supplied)
            temporary.flush()
            desired = installer.read_private(Path(temporary.name))
        if credentials_file.exists():
            installer.require(installer.read_private(credentials_file) == desired,
                              'WEB credentials differ; refusing an implicit rotation')
        else:
            with credentials_file.open('x') as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(desired, stream)
    if not credentials_file.exists():
        desired = {'secret': _dd_secret(controller.ROOT / '.local/mtproto-dd/access.json'),
                   'base_path': secrets.token_hex(10), 'token_key': secrets.token_hex(32)}
        with credentials_file.open('x') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(desired, stream)
    credentials = installer.read_private(credentials_file)
    dd_access = controller.ROOT / '.local/mtproto-dd/access.json'
    if dd_access.exists():
        installer.require(credentials['secret'] == _dd_secret(dd_access),
                          'WEB profile must match the existing local DD backend')
    archive = private / 'assets/source.tar.gz'
    binary, manifest_file = private / 'tproxy-server-linux-amd64', private / 'build.json'
    cached = False
    if binary.is_file() and manifest_file.is_file():
        manifest = json.loads(manifest_file.read_text())
        if manifest.get('source_commit') == installer.SOURCE_COMMIT and manifest.get('source_sha256') == installer.SOURCE_SHA256:
            installer.read_binary(binary, manifest.get('binary_sha256', ''))
            cached = True
    if not cached:
        archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != installer.SOURCE_SHA256:
            url = 'https://codeload.github.com/telegramdesktop/tproxy-server/tar.gz/' + installer.SOURCE_COMMIT
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(32 * 1024 * 1024 + 1)
            installer.require(len(data) <= 32 * 1024 * 1024
                              and hashlib.sha256(data).hexdigest() == installer.SOURCE_SHA256,
                              'Official WEB source download failed SHA256 verification')
            with archive.open('wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
        with tempfile.TemporaryDirectory(prefix='artifact-', dir=private) as temporary:
            candidate = Path(temporary) / 'tproxy-server'
            manifest = builder.build(archive, candidate)
            candidate.replace(binary)
        write_private(manifest_file, json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    access = installer.client_access(credentials, settings)
    write_private(private / 'access.json', json.dumps(access, indent=2) + '\n')
    write_private(private / 'access.md', '# Telegram WEB\n\n[Подключить в Telegram](' + access['link'] + ')\n\n'
                  'Нужен официальный Telegram версии 13.0 или новее для Android/iOS с поддержкой типа WEB. '
                  'Для Telegram на Android с нашей ссылкой технический минимум — 12.10.4; 12.10.2–12.10.3 не поддерживают путь в адресе. '
                  'На Android также нужен совместимый Android System WebView. Обычные MTProto и SOCKS5 настраиваются отдельно.\n\n'
                  'Если профиль добавлялся до смены домена, импортируйте свежую ссылку выше: старые профили сами не обновляются.\n\n'
                  'Сервер WEB: `' + access['server'] + '`\n\nSecret: `' + access['secret'] + '`\n\n'
                  'Корень домена в браузере отвечает 404: это нормально, подключайтесь по ссылке выше.\n\n'
                  'Выходы резервируются через VPN Auto. Сам вход WEB пока один.\n')
    write_private(private / 'nginx-location.conf', installer.nginx_location(credentials, settings))
    write_private(private / 'config.json', installer.config_text(credentials, settings))
    write_private(private / 'proof-settings.json', json.dumps({
        'origin': f'https://{settings.hostname}:{controller.port("VPN_MONITORING_HTTPS_PORT")}',
        'hostname': settings.hostname, 'base_path': credentials['base_path'], 'secret': credentials['secret'],
    }, indent=2) + '\n')
    return {'private': private, 'binary': binary, 'credentials': credentials_file,
            'binary_sha256': manifest['binary_sha256']}


def deploy(controller=None, *, previous_hostname=None):
    if controller is None:
        import vpnctl as controller
    prepared = prepare(controller)
    entry = controller.inventory()['entry']
    with tempfile.TemporaryDirectory(prefix='telegram-web-', dir=controller.ROOT / '.local') as temporary:
        folder = Path(temporary)
        shutil.copyfile(prepared['binary'], folder / 'tproxy-server')
        shutil.copyfile(prepared['credentials'], folder / 'credentials.json')
        (folder / 'credentials.json').chmod(0o600)
        stage = controller.upload(entry['name'], folder, ['install_web_proxy.py'])
        expected = '/opt/vpn-infra/staging/' + entry['name'] + '/' + folder.name
        installer.require(stage == expected, 'Unexpected WEB private staging directory')
        try:
            action = 'retarget-hostname' if previous_hostname is not None else 'install'
            arguments = [stage + '/install_web_proxy.py', action, '--binary', stage + '/payload/tproxy-server',
                '--binary-sha256', prepared['binary_sha256'],
                '--secrets-file', stage + '/payload/credentials.json']
            if previous_hostname is not None:
                installer.validate_hostname(previous_hostname)
                arguments.extend(['--previous-hostname', previous_hostname])
            response = controller.remote(entry['name'], 'sudo python3 -B ' + shlex.join(arguments), capture=True)
            result = json.loads(response.stdout)
            accepted = ('retargeted', 'already_retargeted') if previous_hostname is not None else ('installed', 'already_installed')
            installer.require(result.get('unit') == installer.UNIT
                              and any(result.get(key) is True for key in accepted),
                              'The entry server returned no verified WEB installation state')
            return result
        finally:
            controller.remote(entry['name'], 'sudo rm -rf -- ' + shlex.quote(stage))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--previous-hostname', help='Explicitly migrate only the existing WEB relay hostname')
    args = parser.parse_args()
    if args.prepare_only and args.previous_hostname:
        parser.error('--previous-hostname cannot be combined with --prepare-only')
    try:
        if args.prepare_only:
            result = prepare()
            print(json.dumps({'prepared': True, 'binary_sha256': result['binary_sha256'],
                              'credentials_and_access': 'saved privately', 'server_changes': False}))
        else:
            print(json.dumps(deploy(previous_hostname=args.previous_hostname)))
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        parser.exit(1, 'deploy-web-proxy: ' + detail + '\n')


if __name__ == '__main__':
    main()
