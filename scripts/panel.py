#!/usr/bin/env python3
"""Loopback-only panel API client, run as root on the entry server."""
import atexit
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import ssl
import secrets
import time
import urllib.parse
import urllib.request

class Panel:
    def __init__(self):
        with sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True) as db:
            self.settings=dict(db.execute('SELECT key,value FROM settings'))
        self.token=os.environ.get('VPN_PANEL_TOKEN')
        self.token_id=None
        if not self.token:
            # Root-only automation token: ten-minute lifetime, removed at exit.
            # Existing tokens/passwords are never rotated or exposed.
            self.token=secrets.token_urlsafe(36)
            now=int(time.time()*1000)
            with sqlite3.connect('/etc/x-ui/x-ui.db',timeout=15) as db:
                self.token_id=db.execute('INSERT INTO api_tokens(name,token,enabled,created_at,scope,expires_at) VALUES(?,?,1,?,?,?)',('vpn-infra-'+secrets.token_hex(6),hashlib.sha256(self.token.encode()).hexdigest(),now,'admin',now+600000)).lastrowid
            atexit.register(self.close)
        # Only the local loopback endpoint is used. SSH protects remote access.
        self.context=ssl._create_unverified_context()
        self.base='https://127.0.0.1:'+self.settings.get('webPort','2053')+'/'+self.settings.get('webBasePath','/').strip('/')+'/panel/api/'
        self.base=self.base.replace('//panel','/panel')

    def close(self):
        if self.token_id:
            with sqlite3.connect('/etc/x-ui/x-ui.db',timeout=15) as db:db.execute('DELETE FROM api_tokens WHERE id=?',(self.token_id,))
            self.token_id=None

    def request(self, path, fields=None):
        body=None if fields is None else urllib.parse.urlencode(fields).encode()
        req=urllib.request.Request(self.base+path,data=body,headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req,context=self.context,timeout=30) as res: value=json.load(res)
        if not value.get('success'):raise RuntimeError('Panel API rejected request: '+str(value.get('msg')))
        return value.get('obj')

    def template(self):
        with sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True) as db:
            return json.loads(db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0])

    def save(self, template):
        return self.request('xray/update',{'xraySetting':json.dumps(template),'outboundTestUrl':self.settings.get('xrayOutboundTestUrl','https://www.google.com/generate_204')})

if __name__=='__main__':
    p=Panel();status=p.request('server/status')
    print('Panel API authenticated; template outbounds:',len(p.template()['outbounds']))
