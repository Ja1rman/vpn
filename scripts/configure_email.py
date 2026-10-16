#!/usr/bin/env python3
"""Render private SMTP settings and optionally hot-reload Alertmanager."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from vpnctl import ROOT, inventory, remote, refresh_alertmanager


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
    port = int(settings.get('port', 465))
    if port not in {465, 587}:
        raise ValueError('Use implicit TLS465 or STARTTLS587')
    # Fail closed if the tracked routing template changes; preserve all grouping,
    # inhibition and timing rules verbatim rather than reconstructing them.
    if base.count('  resolve_timeout: 5m\n') != 1 or \
            base.count('  receiver: web-only\n') != 1 or base.count('  - name: web-only\n') != 1:
        raise ValueError('Unexpected Alertmanager base template; review routing first')
    smtp = {'smtp_smarthost': settings['host'] + ':' + str(port),
            'smtp_from': sender, 'smtp_auth_username': settings['username'],
            'smtp_auth_password': settings['password']}
    global_lines = ''.join('  ' + key + ': ' + json.dumps(value) + '\n' for key, value in smtp.items())
    global_lines += '  smtp_require_tls: true\n'
    title = '[VPN][{{ .Status | toUpper }}] {{ .CommonLabels.alertname }} / {{ .CommonLabels.host }}'
    text = ('{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}\n'
            'Status: {{ .Status }}\n{{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }}\n{{ end }}\n{{ end }}')
    receiver = '  - name: email\n    email_configs:\n'
    for address in recipients:
        receiver += ('      - to: ' + json.dumps(address) + '\n        send_resolved: true\n'
                     '        force_implicit_tls: ' + ('true' if port == 465 else 'false') + '\n'
                     '        headers:\n          Subject: ' + json.dumps(title) + '\n'
                     '        text: ' + json.dumps(text) + '\n')
    return base.replace('  resolve_timeout: 5m\n', '  resolve_timeout: 5m\n' + global_lines) \
               .replace('  receiver: web-only\n', '  receiver: email\n') \
               .replace('  - name: web-only\n', receiver)


def check_auth(settings):
    # Credentials travel on SSH stdin, never in argv, environment dumps or logs.
    code = '''import json,ssl,smtplib,sys
c=json.load(sys.stdin)
try:
 if int(c['port'])==465:
  smtp=smtplib.SMTP_SSL(c['host'],int(c['port']),timeout=20,context=ssl.create_default_context())
 else:
  smtp=smtplib.SMTP(c['host'],int(c['port']),timeout=20);smtp.ehlo();smtp.starttls(context=ssl.create_default_context())
 with smtp:
  smtp.ehlo();smtp.login(c['username'],c['password'])
 print('SMTP TLS and authentication verified')
except Exception as e:
 print('SMTP authentication check failed: '+type(e).__name__);sys.exit(1)
'''
    remote(inventory()['entry']['name'], 'python3 -c ' + shlex.quote(code), json.dumps(settings).encode())


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
    for path in [ROOT / '.local/alertmanager.yml', ROOT / '.local/rendered/monitoring/alertmanager/alertmanager.yml']:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_text(config)
        path.chmod(0o600)
    print('Private email configuration rendered; credentials and recipients are not printed')
    if args.apply:
        refresh_alertmanager()
    if args.publish_secret:
        subprocess.run(['gh', 'secret', 'set', 'VPN_ALERTMANAGER_CONFIG', '--repo', 'Ja1rman/vpn',
                        '--env', 'production'], input=config.encode(), check=True, stdout=subprocess.DEVNULL)
        print('Saved production Secret VPN_ALERTMANAGER_CONFIG; CI was not dispatched')


if __name__ == '__main__':
    main()
