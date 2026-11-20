#!/usr/bin/env python3
"""Render private SMTP settings and optionally hot-reload Alertmanager."""
from vpn_env import env as env_value, port as env_port, expand as env_expand, load_json as load_network_json
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from vpnctl import ROOT, inventory, remote, upload


def build_config(settings, base):
    for field in ['host', 'username', 'password', 'to']:
        if not settings.get(field):
            raise ValueError('Missing SMTP setting: ' + field)
    email = r'[^@\s<>\r\n]+@[^@\s<>\r\n]+\.[^@\s<>\r\n]+'
    recipients = settings['to']
    sender = settings.get('from', settings['username'])
    if not isinstance(recipients, list) or not recipients or \
            any(not re.fullmatch(email, r) for r in recipients) or not re.fullmatch(email, sender):
        raise ValueError('Invalid SMTP sender or recipient')
    if not re.fullmatch(r'[a-zA-Z0-9.-]+', settings['host']):
        raise ValueError('Invalid SMTP hostname')
    port = int(settings.get('port', env_port('VPN_SMTP_PORT')))
    if port not in {env_port('VPN_SMTP_PORT'), env_port('VPN_SMTP_STARTTLS_PORT')}:
        raise ValueError('Use implicit TLS465 or STARTTLS587')
    # Fail closed if the tracked routing template changes; preserve all grouping,
    # inhibition and timing rules verbatim rather than reconstructing them.
    if any(base.count(line) != 1 for line in ('  resolve_timeout: 5m\n', '\n  receiver: web-only\n',
                                              '\n  - name: web-only\n', '\n  - name: node-outage\n')):
        raise ValueError('Unexpected Alertmanager base template; review routing first')
    smtp = {'smtp_smarthost': settings['host'] + ':' + str(port),
            'smtp_from': sender, 'smtp_auth_username': settings['username'],
            'smtp_auth_password': settings['password']}
    global_lines = ''.join('  ' + key + ': ' + json.dumps(value) + '\n' for key, value in smtp.items())
    global_lines += '  smtp_require_tls: true\n'
    title = ('[VPN][{{ .Status | toUpper }}] {{ if eq .CommonLabels.alertname "NodeUnavailableNotification" }}'
             'NodeUnavailable{{ else }}{{ .CommonLabels.alertname }}{{ end }} / {{ .CommonLabels.host }}')
    text = ('{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}\n'
            'Status: {{ .Status }}\n{{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }}\n{{ end }}\n{{ end }}')
    def email_configs(send_resolved):
        return '    email_configs:\n' + ''.join(
            '      - to: ' + json.dumps(address) + '\n'
            '        send_resolved: ' + json.dumps(send_resolved) + '\n'
            '        force_implicit_tls: ' + json.dumps(port == env_port('VPN_SMTP_PORT')) + '\n'
            '        headers:\n          Subject: ' + json.dumps(title) + '\n'
            '        text: ' + json.dumps(text) + '\n'
            for address in recipients
        )

    return base.replace('  resolve_timeout: 5m\n', '  resolve_timeout: 5m\n' + global_lines) \
               .replace('\n  receiver: web-only\n', '\n  receiver: email\n') \
               .replace('\n  - name: web-only\n', '\n  - name: web-only\n  - name: email\n' + email_configs(True)) \
               .replace('\n  - name: node-outage\n', '\n  - name: node-outage\n' + email_configs(False))


def check_auth(settings):
    # Credentials travel on SSH stdin, never in argv, environment dumps or logs.
    code = env_expand("import json,ssl,smtplib,sys\nc=json.load(sys.stdin)\ntry:\n if int(c['port'])==${VPN_SMTP_PORT}:\n  smtp=smtplib.SMTP_SSL(c['host'],int(c['port']),timeout=20,context=ssl.create_default_context())\n else:\n  smtp=smtplib.SMTP(c['host'],int(c['port']),timeout=20);smtp.ehlo();smtp.starttls(context=ssl.create_default_context())\n with smtp:\n  smtp.ehlo();smtp.login(c['username'],c['password'])\n print('SMTP TLS and authentication verified')\nexcept Exception as e:\n print('SMTP authentication check failed: '+type(e).__name__);sys.exit(1)\n")
    remote(inventory()['entry']['name'], 'python3 -c ' + shlex.quote(code), json.dumps(settings).encode())


def apply_alerting(config):
    entry = inventory()['entry']['name']
    with tempfile.TemporaryDirectory(prefix='alerting-', dir=ROOT / '.local') as tmp:
        folder = Path(tmp)
        for name in ('alertmanager', 'prometheus'):
            (folder / name).mkdir()
        (folder / 'alertmanager/alertmanager.yml').write_text(config)
        (folder / 'prometheus/alerts.yml').write_bytes((ROOT / 'monitoring/prometheus/alerts.yml').read_bytes())
        stage = upload(entry, folder, ['refresh_failover_alerts.py'])
        try:
            remote(entry, 'sudo python3 -B ' + shlex.join([
                stage + '/refresh_failover_alerts.py', stage + '/payload', '--alerting-only', '--apply',
            ]))
        finally:
            remote(entry, 'sudo rm -rf -- ' + shlex.quote(stage))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--publish-secret', action='store_true')
    args = parser.parse_args()
    settings = json.loads((ROOT / '.local/smtp.json').read_text())
    settings['username'] = os.environ.get('VPN_SMTP_USERNAME') or settings.get('username', '')
    settings['password'] = os.environ.get('VPN_SMTP_PASSWORD') or settings.get('password', '')
    config = build_config(settings, (ROOT / 'monitoring/alertmanager/alertmanager.yml').read_text())
    if args.apply:
        check_auth(settings)
        apply_alerting(config)
    for path in [ROOT / '.local/alertmanager.yml', ROOT / '.local/rendered/monitoring/alertmanager/alertmanager.yml']:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_text(config)
        path.chmod(0o600)
    print('Private email configuration rendered; credentials and recipients are not printed')
    if args.publish_secret:
        subprocess.run(['gh', 'secret', 'set', 'VPN_ALERTMANAGER_CONFIG', '--repo', 'Ja1rman/vpn',
                        '--env', 'production'], input=config.encode(), check=True, stdout=subprocess.DEVNULL)
        print('Saved production Secret VPN_ALERTMANAGER_CONFIG; CI was not dispatched')


if __name__ == '__main__':
    main()
