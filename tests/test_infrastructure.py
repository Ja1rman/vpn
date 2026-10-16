import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import sqlite3

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import render
from activate_balancer import change_template
from migrate_direct_inbounds import add_routes, TARGETS
import migrate_direct_inbounds as migration

class SafetyInvariants(unittest.TestCase):
    def test_template_save_refuses_concurrent_panel_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT)')
                db.execute('INSERT INTO settings VALUES (?,?)',('xrayTemplateConfig','edited-by-owner'))
            with patch.object(migration,'DB',str(path)):
                with self.assertRaises(RuntimeError):migration.save_template('stale-snapshot','migration')
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT value FROM settings').fetchone()[0],'edited-by-owner')

    def test_legacy_migration_is_route_only_and_idempotent(self):
        old={'inbounds':[{'port':36307,'settings':{'secretKey':'keep','peers':[{'publicKey':'keep'}]}}],
             'outbounds':[{'tag':'direct','protocol':'freedom'},
                          {'tag':'vpn-egress-pool','protocol':'socks','settings':{'address':'127.0.0.1','port':11090}}],
             'routing':{'domainStrategy':'AsIs','rules':[{'ip':['geoip:private'],'outboundTag':'blocked'}]}}
        snapshot=copy.deepcopy(old)
        new=add_routes(old)
        self.assertEqual(old,snapshot)
        self.assertEqual(new['inbounds'],old['inbounds'])
        self.assertEqual(new['outbounds'],old['outbounds'])
        self.assertEqual(new['routing']['rules'][:1],old['routing']['rules'])
        self.assertEqual([r['inboundTag'][0] for r in new['routing']['rules'][1:]],list(TARGETS))
        self.assertEqual(add_routes(new),new)
        old['routing']['rules'].append({'inboundTag':['in-36307-udp'],'network':'tcp','outboundTag':'direct'})
        with self.assertRaises(ValueError):add_routes(old)

    def test_only_selected_routes_change(self):
        old={'inbounds':[{'port':443,'settings':{'clients':[{'id':'existing-client'}]}}], 'outbounds':[{'tag':'legacy','protocol':'vless'}], 'routing':{'rules':[{'inboundTag':['api'],'outboundTag':'api'},{'ip':['geoip:private'],'outboundTag':'blocked'},{'inboundTag':['protected'],'outboundTag':'legacy'},{'inboundTag':['other'],'outboundTag':'direct'}]}, 'policy':{'keep':'unchanged'}}
        snapshot=copy.deepcopy(old)
        new,count=change_template(old,['legacy'],11090)
        self.assertEqual(count,1)
        self.assertEqual(old,snapshot)
        self.assertEqual(new['inbounds'],old['inbounds'])
        self.assertEqual(new['routing']['rules'][:2],old['routing']['rules'][:2])
        self.assertEqual(new['routing']['rules'][3],old['routing']['rules'][3])
        self.assertEqual(new['policy'],old['policy'])
        self.assertEqual(new['outbounds'][-1]['settings'],{'address':'127.0.0.1','port':11090})

    def test_pool_is_fail_closed_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=render.ROOT;render.ROOT=Path(tmp)
            try:
                (render.ROOT/'out.json').write_text(json.dumps({'protocol':'vless','settings':{'address':'203.0.113.1'}}))
                inv={'nodes':[{'name':'example','outbounds':['out.json']}],'balancer':{'socks_port':11090,'api_port':11091,'strategy':'roundRobin','probe_interval':'10s','probe_url':'https://example.com/'}}
                config=render.build_balancer(inv)
                self.assertTrue(all(i['listen']=='127.0.0.1' for i in config['inbounds']))
                self.assertEqual(config['outbounds'][0]['protocol'],'blackhole')
                self.assertEqual(config['routing']['balancers'][0]['fallbackTag'],'blocked')
                self.assertNotIn('freedom',[o['protocol'] for o in config['outbounds']])
                (render.ROOT/'out.json').write_text(json.dumps({'protocol':'freedom'}))
                with self.assertRaises(ValueError):render.build_balancer(inv)
            finally:render.ROOT=root

if __name__=='__main__':unittest.main()
