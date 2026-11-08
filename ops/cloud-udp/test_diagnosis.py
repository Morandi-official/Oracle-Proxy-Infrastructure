import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('identity',ROOT/'ops/oracle-project/cloud_udp_identity.py')
identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
KEY=base64.b64encode(b'A'*32).decode()
OTHER=base64.b64encode(b'B'*32).decode()


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)/'diagnostics'
        self.calls=[]
        self.snapshot={'error':None,'budget':{'guard_blocked':False},'users':[{'id':'existing','name':'Real user','expires':None}],
                       'peers':[{'public_key':OTHER,'user_id':'existing','name':'Real PC','owned':True,'present':True}],
                       'server_public_key':OTHER}
        self.addCleanup(patch.stopall)
        patch.object(identity,'STATE',self.root).start()
        patch.object(identity.time,'time',return_value=1800000000).start()
        patch.object(identity,'rpc',side_effect=self.rpc).start()
        patch.object(identity,'kernel_has_peer',return_value=False).start()
        # Production requires root-owned files; permit testing those checks as a
        # normal CI user while retaining actual filesystem modes and contents.
        original=Path.stat
        def stat(path,*args,**kwargs):
            value=list(original(path,*args,**kwargs));value[4]=0
            return os.stat_result(value)
        patch.object(Path,'stat',stat).start()

    def request(self,action='prepare',key=KEY):
        return {'action':action,'probe_id':'a'*32,'public_key':key}

    def rpc(self,operation,data):
        self.calls.append((operation,copy.deepcopy(data)))
        snapshot=self.snapshot
        if operation=='user.save':
            snapshot['users'].append({'id':'diagnostic','name':data['name'],'expires':data['expires_at']})
        elif operation=='peer.create':
            snapshot['peers'].append({'public_key':data['public_key'],'user_id':data['user_id'],'name':data['name'],
                                     'owned':True,'present':True,'handshake':0,'usage':{'rx':0,'tx':0},'allowed_ips':['10.77.0.222/32']})
        elif operation=='peer.delete':snapshot['peers']=[p for p in snapshot['peers'] if p['public_key']!=data['public_key']]
        elif operation=='user.delete':snapshot['users']=[u for u in snapshot['users'] if u['id']!=data['user_id']]
        value=copy.deepcopy(snapshot)
        if operation=='user.save':value['saved_user_id']='diagnostic'
        return value

    def test_reconcile_recovers_only_exact_failed_run_markers(self):
        request={**self.request(),'probe_id':identity.RECOVER_PROBES[0]}
        identity.execute(request)
        result=identity.reconcile_owned()
        self.assertEqual(result['errors'],[])
        self.assertEqual(result['recovered'],[{'probe_id':request['probe_id'],'cleaned':True}])
        self.assertEqual(len(self.snapshot['users']),1)
        self.assertEqual(self.snapshot['peers'][0]['public_key'],OTHER)

    def test_reconcile_refuses_changed_marker_owner_before_mutation(self):
        request={**self.request(),'probe_id':identity.RECOVER_PROBES[0]}
        identity.execute(request)
        path=self.root/(request['probe_id']+'.json');value=json.loads(path.read_text());value['name']='Real user';path.write_text(json.dumps(value));self.calls.clear()
        with self.assertRaisesRegex(ValueError,'OWNER_MISMATCH'):identity.reconcile_owned()
        self.assertEqual(self.calls,[])

    def test_host_audit_is_read_only_and_bound_to_active_owned_marker(self):
        with patch.object(identity,'host_audit',return_value={'host':{'scope':'CURRENT_HOST_ONLY'}}) as audit:
            with self.assertRaises(ValueError):identity.execute(self.request('host-audit'))
            audit.assert_not_called()
            identity.execute(self.request())
            before=copy.deepcopy(self.snapshot);self.calls.clear()
            self.assertEqual(identity.execute(self.request('host-audit')),{'host':{'scope':'CURRENT_HOST_ONLY'}})
            self.assertEqual(self.calls,[('state',{})]);self.assertEqual(self.snapshot,before)
            audit.reset_mock()
            with self.assertRaises(ValueError):identity.execute(self.request('host-audit',OTHER))
            audit.assert_not_called()
            identity.execute(self.request('cleanup'))
            with self.assertRaises(ValueError):identity.execute(self.request('host-audit'))
            audit.assert_not_called()

    def test_expiring_separate_identity_and_exact_cleanup(self):
        identity.execute(self.request())
        saved=next(d for op,d in self.calls if op=='user.save')
        self.assertEqual(saved['expires_at'],1800000900)
        self.assertEqual(saved['quota_bytes'],32*1024*1024)
        self.assertEqual(saved['device_limit'],1)
        self.assertEqual(identity.execute(self.request('cleanup')),{'cleaned':True,'pending_diagnostics':[]})
        self.assertEqual(self.snapshot['users'],[{'id':'existing','name':'Real user','expires':None}])
        self.assertEqual(self.snapshot['peers'][0]['public_key'],OTHER)
        self.assertEqual(len(self.snapshot['peers']),1)
        identity.execute(self.request('cleanup'))
        self.assertEqual(sum(op=='user.delete' for op,d in self.calls),1)

    def test_foreign_key_cannot_observe_or_delete_owned_identity(self):
        identity.execute(self.request())
        for action in ('prepare','observe','cleanup'):
            with self.assertRaisesRegex(ValueError,'OWNER_MISMATCH'):
                identity.execute(self.request(action,OTHER))
        self.assertFalse(any(op.endswith('.delete') for op,d in self.calls))

    def test_cleanup_still_allowed_when_budget_guard_blocks_new_tests(self):
        identity.execute(self.request());self.snapshot['budget']['guard_blocked']=True
        with self.assertRaisesRegex(ValueError,'POLICY_NOT_READY'):identity.execute(self.request('observe'))
        self.assertTrue(identity.execute(self.request('cleanup'))['cleaned'])

    def test_response_loss_recovers_exact_pre_recorded_identity(self):
        identity.execute(self.request())
        path=self.root/('a'*32+'.json');marker=json.loads(path.read_text());marker['user_id']=None;path.write_text(json.dumps(marker))
        identity.execute(self.request('cleanup'))
        self.assertEqual(len(self.snapshot['users']),1)
        self.assertEqual(len(self.snapshot['peers']),1)

    def test_preexisting_key_refused_without_mutation(self):
        with self.assertRaisesRegex(ValueError,'PREEXISTING'):identity.execute(self.request(key=OTHER))
        self.assertFalse(any(op!='state' for op,d in self.calls))

    def test_changed_peer_owner_refused(self):
        identity.execute(self.request())
        self.snapshot['peers'][-1]['user_id']='existing'
        with self.assertRaisesRegex(ValueError,'OWNER_MISMATCH'):identity.execute(self.request('cleanup'))
        self.assertFalse(any(op.endswith('.delete') for op,d in self.calls))

    def test_symlink_marker_refused(self):
        self.root.mkdir(mode=0o700);target=Path(self.temporary.name)/'foreign';target.write_text('{}')
        (self.root/('a'*32+'.json')).symlink_to(target)
        with self.assertRaisesRegex(ValueError,'UNTRUSTED'):identity.execute(self.request())
        self.assertEqual(self.calls,[])

    def test_cleanup_cannot_succeed_if_kernel_peer_remains(self):
        identity.execute(self.request())
        with patch.object(identity,'kernel_has_peer',return_value=True):
            with self.assertRaisesRegex(ValueError,'CLEANUP_NOT_VERIFIED'):
                identity.execute(self.request('cleanup'))
        marker=json.loads((self.root/('a'*32+'.json')).read_text())
        self.assertFalse(marker['cleaned'])

    def test_expired_identity_cannot_be_renewed_but_can_be_cleaned(self):
        identity.execute(self.request())
        with patch.object(identity.time,'time',return_value=1800000901):
            with self.assertRaisesRegex(ValueError,'LEASE_EXPIRED'):identity.execute(self.request())
            self.assertTrue(identity.execute(self.request('cleanup'))['cleaned'])

    def test_invalid_or_path_injected_request_refused(self):
        for data in ({}, {**self.request(),'probe_id':'../x'}, {**self.request(),'action':'user.delete'},
                     {**self.request(),'public_key':'invalid'}, {**self.request(),'extra':'value'}):
            with self.assertRaises(ValueError):identity.validate(data)


class ControlRpcDiagnosticsTest(unittest.TestCase):
    def test_control_error_code_survives_without_raw_exception_text(self):
        from types import SimpleNamespace
        account=SimpleNamespace(pw_uid=1001,pw_gid=1001)
        for output,expected in ((json.dumps({'control_error':'USER_LIMIT'}),'USER_LIMIT'),
                                (json.dumps({'control_error':'secret value with spaces'}),'DIAGNOSTIC_CONTROL_RPC_FAILED')):
            result=SimpleNamespace(returncode=2,stdout=output)
            with patch.object(identity.pwd,'getpwnam',return_value=account),patch.object(identity.subprocess,'run',return_value=result) as run:
                with self.assertRaisesRegex(ValueError,expected):identity.rpc('state',{})
                compile(run.call_args.args[0][3],'<rpc-code>','exec')


class ConfigurationTest(unittest.TestCase):
    def test_actual_export_has_one_udp_outbound_and_no_route_or_direct_fallback(self):
        spec=importlib.util.spec_from_file_location('probe',Path(__file__).with_name('probe.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        info={'server_public_key':OTHER,'allowed_ips':['10.77.0.222/32','fd42:6f70:78:77::a4d:de/128']}
        cfg=module.configuration(info,KEY,'152.67.156.100',8443,18790)
        self.assertFalse(cfg['tun']['enable'])
        self.assertEqual(cfg['rules'],['MATCH,Proxy UDP'])
        self.assertEqual(cfg['proxy-groups'],[])
        self.assertEqual(len(cfg['proxies']),1)
        self.assertEqual(cfg['proxies'][0]['server'],'152.67.156.100')
        self.assertEqual(cfg['proxies'][0]['port'],8443)
        self.assertEqual(cfg['proxies'][0]['dns'],['https://1.1.1.1/dns-query'])

    def test_failed_proxy_never_retries_target_directly(self):
        from unittest.mock import MagicMock
        spec=importlib.util.spec_from_file_location('probe',Path(__file__).with_name('probe.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        client=MagicMock();client.request.side_effect=OSError('closed proxy')
        with patch.object(module.http.client,'HTTPConnection',return_value=client) as connection:
            result=module.fetch(18790,'1.1.1.1')
            connection.assert_called_once_with('127.0.0.1',18790,timeout=12)
        self.assertEqual(result,{'error_category':'OSError'})


class KernelEndpointPlan(unittest.TestCase):
    def test_sticky_source_primes_working_alias_and_tests_exact_same_six_targets(self):
        spec=importlib.util.spec_from_file_location('kernel_plan',Path(__file__).with_name('kernel_probe.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        normal=module.endpoint_order();sticky=module.endpoint_order(True)
        self.assertEqual(len(sticky),6);self.assertEqual(set(sticky),set(normal))
        self.assertEqual(sticky[0],('152.67.154.225',443))
        self.assertEqual(normal[0],('152.67.154.225',443))

if __name__=='__main__':unittest.main()
