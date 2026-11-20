import copy
import fcntl
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_environment import configure
configure()
from vpn_env import env,port
import install_tcp_demux as helper


class ScopedDemuxTests(unittest.TestCase):
    def settings(self):
        address=env('VPN_TEST_ADDRESS_A');public=port('VPN_WEB_HTTPS_PORT');listen=port('VPN_TEST_CANARY_PORT')
        loop=env('VPN_LOOPBACK_IP')
        return {'address':address,'interface':'testiface','public_port':public,'listen_port':listen,
                'classifier':{'listen':f'{address}:{listen}','redirected_from':f'{address}:{public}',
                              'default_target':f'{loop}:{public}','tls_sni_targets':{}}}

    def test_settings_accept_unicast_nat_address_without_public_requirement(self):
        value=self.settings()
        with patch.object(helper.ipaddress.IPv4Address,'is_global',property(lambda _:False)):
            self.assertEqual(helper.settings(value),value)
        bad=copy.deepcopy(value);bad['classifier']['redirected_from']=bad['classifier']['listen']
        with self.assertRaises(RuntimeError):helper.settings(bad)
        bad=copy.deepcopy(value);bad['address']=env('VPN_LOOPBACK_IP')
        with self.assertRaises(RuntimeError):helper.settings(bad)

    def test_only_exact_external_initial_syn_is_redirected(self):
        value=self.settings();rule=helper.rule(value)
        self.assertIn('--syn',rule)
        self.assertEqual(rule[rule.index('--ctstate')+1],'NEW')
        self.assertEqual(rule[rule.index('-i')+1],value['interface'])
        self.assertEqual(rule[rule.index('-d')+1],value['address']+'/32')
        self.assertNotIn('OUTPUT',rule)
        drain=helper.rule(value,True)
        self.assertEqual(drain[drain.index('--ctstate')+1],'INVALID')
        self.assertEqual(drain[-1],'RETURN')
        self.assertNotIn('REDIRECT',drain)

    def test_detach_retains_hook_until_redirected_connections_drain(self):
        operations=[]
        with patch.object(helper,'present',return_value=True),patch.object(helper,'add',side_effect=lambda *a,**k:operations.append(('add',k))),patch.object(helper,'remove',side_effect=lambda *a,**k:operations.append(('remove',k))),patch.object(helper,'active_connections',return_value=1):
            self.assertTrue(helper.detach(self.settings()))
        self.assertEqual(operations,[('add',{'drain':True}),('remove',{})])
        operations=[]
        with patch.object(helper,'present',return_value=True),patch.object(helper,'add',side_effect=lambda *a,**k:operations.append(('add',k))),patch.object(helper,'remove',side_effect=lambda *a,**k:operations.append(('remove',k))),patch.object(helper,'active_connections',return_value=0):
            self.assertFalse(helper.detach(self.settings()))
        self.assertEqual(operations[-1],('remove',{'drain':True}))

    def test_rollback_uses_sealed_nat_state_even_if_binary_or_config_missing(self):
        state={'id':'own-transaction','status':'armed','nat_settings':helper.nat_settings(self.settings())}
        with patch.object(helper,'sealed_state',return_value=state),patch.object(helper,'installed',side_effect=AssertionError('manifest must not block rollback')),patch.object(helper,'detach',return_value=False) as detach,patch.object(helper,'atomic'),patch.object(helper,'COMMITTED',MagicMock()),patch.object(helper,'command') as command:
            result=helper.rollback('own-transaction')
        detach.assert_called_once_with(state['nat_settings'])
        self.assertTrue(result['rolled_back'])
        self.assertEqual(state['status'],'rolled_back')
        self.assertTrue(any('--no-block' in call.args for call in command.call_args_list))

    def test_wrong_transaction_cannot_remove_another_owned_rule(self):
        with patch.object(helper,'sealed_state',return_value={'id':'newer','status':'armed'}),patch.object(helper,'detach') as detach:
            with self.assertRaises(RuntimeError):helper.rollback('older')
        detach.assert_not_called()

    def test_external_proof_is_strict_and_original_runtime_guard_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);settings=root/'settings.json';settings.write_text('{}')
            state={'id':'test','status':'armed','deadline':time.time()+100,'settings':helper.digest(settings.read_bytes()),'baseline':{'files':{},'processes':{}}}
            with patch.object(helper,'installed',return_value=self.settings()),patch.object(helper,'private_json',return_value=state),patch.object(helper,'SETTINGS',settings),patch.object(helper,'snapshot',return_value=state['baseline']),patch.object(helper,'present',return_value=True),patch.object(helper,'atomic'):
                with self.assertRaises(RuntimeError):helper.commit({'transaction':'test','original_tls':True,'new_protocols':1})
                with self.assertRaises(RuntimeError):helper.commit({'transaction':'another','original_tls':True,'new_protocols':True})
                self.assertTrue(helper.commit({'transaction':'test','original_tls':True,'new_protocols':True})['committed'])
                state['status']='armed'
                with patch.object(helper,'snapshot',return_value={'processes':{'changed':True}}):
                    with self.assertRaises(RuntimeError):helper.commit({'transaction':'test','original_tls':True,'new_protocols':True})

    def test_lifecycle_is_bound_to_classifier_and_has_resource_limits(self):
        service=helper.service_unit().decode();firewall=helper.firewall_unit().decode()
        for setting in ('MemoryMax=128M','CPUQuota=100%','GOMEMLIMIT=96MiB','GOMAXPROCS=2','User='+helper.NAME,'Group='+helper.NAME,'TimeoutStopSec=infinity'):
            self.assertIn(setting,service)
        self.assertNotIn('LoadCredential=',service)
        self.assertNotIn('%d/',service)
        self.assertIn('Wants=network-online.target '+helper.NAME+'-firewall.service',service)
        self.assertIn('BindsTo='+helper.NAME+'.service',firewall)
        self.assertIn('ConditionPathExists='+str(helper.COMMITTED),firewall)

    def test_commit_starts_lifecycle_after_releasing_the_global_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            lock=Path(directory)/'lock'
            def command(*args,**kwargs):
                if '--now' in args:
                    with lock.open('a') as stream:
                        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        fcntl.flock(stream,fcntl.LOCK_UN)
                return MagicMock(returncode=0)
            with patch.object(helper,'LOCK',lock),patch.object(helper.os,'geteuid',return_value=0),patch.object(helper,'private_json',return_value={'original_tls':True,'new_protocols':True}),patch.object(helper,'commit',return_value={'committed':True}),patch.object(helper,'command',side_effect=command) as invoked,patch.object(sys,'argv',['helper','commit','--proof-file',str(Path(directory)/'proof.json')]),patch.object(sys,'stdout',io.StringIO()):
                with patch.object(helper.os, 'umask'):
                    helper.main()
            self.assertTrue(any('--now' in call.args for call in invoked.call_args_list))

    def test_preexisting_unrelated_privileged_account_is_rejected(self):
        from types import SimpleNamespace
        user=SimpleNamespace(pw_uid=0,pw_gid=0,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        group=SimpleNamespace(gr_gid=0)
        with patch.object(helper.pwd,'getpwnam',return_value=user),patch.object(helper.grp,'getgrnam',return_value=group),patch.object(helper,'command') as command:
            with self.assertRaises(RuntimeError):helper.identity(create=True)
        command.assert_not_called()
        with patch.object(helper,'command') as command:
            helper.remove_created_identity({'created':False})
        command.assert_not_called()

    def test_comment_collision_is_not_adopted(self):
        saved=b'-A PREROUTING -m comment --comment "'+helper.COMMENT.encode()+b'" -j RETURN\n'
        def command(*args,**kwargs):
            from types import SimpleNamespace
            return SimpleNamespace(stdout=saved if args[0]=='iptables-save' else b'',returncode=0 if args[0]=='iptables-save' else 1)
        with patch.object(helper,'command',side_effect=command):
            with self.assertRaises(RuntimeError):helper.present(self.settings())

if __name__=='__main__':unittest.main()
