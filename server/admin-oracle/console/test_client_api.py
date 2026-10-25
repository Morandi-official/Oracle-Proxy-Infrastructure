"""Real web credential/session/authorization flow against the real policy engine."""
import base64
import importlib.util
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.hashers import make_password
from django.test import Client, TestCase

from .models import ClientAccount, ClientSession, ClientLoginThrottle
from .tests import HOST

spec=importlib.util.spec_from_file_location('client_policy_tests',Path(__file__).resolve().parents[1]/'control/test_agent.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class ClientApiTests(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.driver=fixture.FakeDriver()
        self.engine=fixture.agent.Engine(Path(self.tmp.name)/'ledger.sqlite3',self.driver)
        self.rpc=patch('console.control.call',side_effect=lambda operation,actor,data:self.engine.dispatch({'operation':operation,'actor':actor,'data':data}))
        self.rpc.start(); self.addCleanup(self.rpc.stop);self.addCleanup(self.tmp.cleanup);self.addCleanup(self.engine.db.close)
        self.engine.tick()
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':{'id':None,'name':'Only me','quota_bytes':100000,'expires_at':None,'enabled':True}})
        self.user=self.engine.snapshot()['users'][0]
        self.account=ClientAccount.objects.create(user_id=self.user['id'],username='client01',password=make_password('test-only-password-012345'))
        self.client=Client(enforce_csrf_checks=True,HTTP_HOST=HOST)

    def login(self,index=3,confirm=True,**extra):
        value={'username':'client01','password':'test-only-password-012345','public_key':base64.b64encode(bytes([index])*32).decode(),'device_name':'Synthetic Win11','client_version':'0.3.0-rc18'}
        value.update(extra)
        authenticated=self.client.post('/api/client/authenticate',json.dumps(value),content_type='application/json',secure=True)
        if authenticated.status_code!=200 or not confirm or not authenticated.json()['registration']['requires_confirmation']:return authenticated
        token=authenticated.json()['token']
        result=self.enroll(token)
        if result.status_code==200:
            data=result.json();data['token']=token
            result.content=json.dumps(data).encode();result._json=data
        return result

    def enroll(self,token,**extra):
        value={'device_name':'My recognized laptop','confirm':True};value.update(extra)
        return self.client.post('/api/client/enroll',json.dumps(value),content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+token)

    def state(self,token,path='/api/client/state'):
        return self.client.get(path,secure=True,HTTP_AUTHORIZATION='Bearer '+token)

    def test_enroll_login_progress_scope_and_no_admin_or_browser_access(self):
        result=self.login();self.assertEqual(result.status_code,200,result.content);value=result.json();token=value['token']
        self.assertEqual(value['account']['device_limit'],3);self.assertEqual(value['account']['device_count'],1)
        self.assertEqual(value['account']['used_bytes'],0);self.assertEqual(value['account']['limit_bytes'],100000)
        self.assertNotIn(token,ClientSession.objects.first().token_hash)
        self.assertEqual(self.state(token).status_code,200)
        for path in ['/api/control','/api/audit','/api/status']:
            self.assertEqual(self.state(token,path).status_code,401)
        self.assertNotIn('users',self.state(token).json());self.assertNotIn('budget',self.state(token).json())
        self.assertEqual(self.client.post('/accounts/signup/',secure=True).status_code,404)
        self.assertEqual(self.client.post('/api/client/login',json.dumps({'username':'client01'}),content_type='application/json',secure=True,HTTP_ORIGIN='https://evil.invalid').status_code,403)

    def test_cap_serialized_idempotence_revocation_and_preserved_usage(self):
        first=self.login().json();self.assertEqual(self.login().status_code,200)
        self.assertEqual(self.login(5).status_code,200);self.assertEqual(self.login(6).status_code,200)
        self.assertEqual(self.login(7).json()['error'],'DEVICE_LIMIT_REACHED')
        key=first['device']['public_key'];self.driver.value['peers'][key]['tx']+=40;self.engine.tick()
        self.engine.dispatch({'operation':'peer.revoke','actor':'github:204281968','data':{'public_key':key}})
        self.assertNotIn('10.250.0.4',self.driver.allowed)
        self.assertEqual(self.engine.used('user',self.user['id'])['tx'],40)
        # Existing bearer cannot retrieve a revoked device, cap is immediately freed.
        credential=ClientSession.objects.get(public_key=key);self.assertIsNotNone(credential)
        ClientLoginThrottle.objects.all().delete()
        self.assertEqual(self.login(8).status_code,200)
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],3)

    def test_disabled_expiry_quota_states_follow_root_without_cross_user_data(self):
        token=self.login().json()['token']
        data={'id':self.user['id'],'name':'Only me','quota_bytes':0,'expires_at':None,'enabled':True}
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':data})
        self.assertEqual(self.state(token).json()['account']['status'],'quota')
        data.update(quota_bytes=100000,expires_at=int(time.time())-1)
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':data})
        self.assertEqual(self.state(token).json()['account']['status'],'expired')
        data.update(enabled=False)
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':data})
        self.assertEqual(self.state(token).json()['account']['status'],'disabled')

    def test_wrong_password_uniform_error_rate_limit_and_no_enrollment(self):
        self.assertEqual(self.login(password='wrong').status_code,401)
        self.assertEqual(self.login(username='missing-user').json()['error'],'INVALID_CREDENTIALS')
        for _ in range(4):self.assertEqual(self.login(password='wrong').status_code,401)
        self.assertEqual(self.login().status_code,429)
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],0)

    def test_password_reset_invalidates_tokens_and_credentials_never_admin(self):
        from .client_api import set_account
        token=self.login().json()['token']
        set_account(None,{'user_id':self.user['id'],'username':'client01','password':'replacement-password-012345','device_limit':3})
        self.assertEqual(self.state(token).status_code,401)
        self.assertEqual(self.login().status_code,401)
        self.assertEqual(self.login(password='replacement-password-012345').status_code,200)
        self.assertFalse(self.client.login(username='client01',password='replacement-password-012345'))

    def test_unified_save_keeps_password_and_usage_then_delete_revokes_every_device(self):
        from .client_api import save_account, delete_account
        token=self.login().json()['token']; key=ClientSession.objects.first().public_key
        self.driver.value['peers'][key]['tx']+=42;self.engine.tick()
        value={'id':self.user['id'],'name':'Renamed','username':'client01','password':'','device_limit':4,'quota_bytes':200000,'expires_at':None,'enabled':True}
        result=save_account(None,value)
        self.assertEqual(result['users'][0]['usage']['tx'],42)
        self.assertEqual(result['users'][0]['device_limit'],4)
        self.assertEqual(self.state(token).status_code,200)
        delete_account(None,{'user_id':self.user['id']})
        self.assertEqual(self.state(token).status_code,401)
        self.assertFalse(ClientAccount.objects.exists());self.assertFalse(self.driver.allowed)
        self.assertEqual(self.engine.snapshot()['users'],[])
        self.assertTrue(next(p for p in self.engine.snapshot()['peers'] if p['public_key']==key)['user_deleted'])
        self.assertEqual(self.engine.used('user',self.user['id'])['tx'],42)
        self.assertEqual(self.login().status_code,401)
        delete_account(None,{'user_id':self.user['id']})  # retry is safe
        with self.assertRaisesRegex(ValueError,'USER_DELETED'): save_account(None,{**value,'password':'new-test-password-123'})

    def test_unified_create_validation_before_mutation_and_partial_failure_stays_disabled(self):
        from .client_api import save_account
        value={'id':None,'name':'New account','username':'new01','password':'test-password-only-123','device_limit':3,'quota_bytes':12345,'expires_at':None,'enabled':True}
        with self.assertRaisesRegex(ValueError,'USERNAME_ALREADY_EXISTS'):save_account(None,{**value,'username':'client01'})
        self.assertEqual(len(self.engine.snapshot()['users']),1)
        with patch('console.client_api.ClientAccount.objects.update_or_create',side_effect=OSError('synthetic database failure')):
            with self.assertRaises(OSError):save_account(None,value)
        pending=next(u for u in self.engine.snapshot()['users'] if u['name']=='New account')
        self.assertFalse(pending['enabled']);self.assertFalse(ClientAccount.objects.filter(username='new01').exists())
        saved=save_account(None,{**value,'id':pending['id']})
        self.assertTrue(next(u for u in saved['users'] if u['id']==pending['id'])['enabled'])

    def test_password_login_alone_never_allocates_a_peer_slot_or_tunnel(self):
        value=self.login(confirm=False).json();token=value['token']
        self.assertEqual(value['account']['device_count'],0)
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],0)
        self.assertEqual(value['registration']['status'],'pending')
        self.assertTrue(value['registration']['requires_slot'])
        self.assertFalse(value['device']['registered']);self.assertIsNone(value['tunnel'])
        self.assertIsNone(self.state(token).json()['tunnel'])
        self.assertEqual(self.enroll(token,confirm=False).status_code,400)
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],0)
        self.assertEqual(self.enroll(token,public_key=base64.b64encode(bytes([9])*32).decode()).status_code,400)
        self.assertEqual(self.enroll('x'*43).status_code,401)
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],0)

    def test_explicit_confirmation_is_idempotent_named_and_audited(self):
        pending=self.login(confirm=False).json();token=pending['token']
        first=self.enroll(token,device_name='My study computer').json()
        again=self.enroll(token,device_name='My study computer').json()
        self.assertEqual(first['registration'],again['registration'])
        self.assertEqual(first['registration']['status'],'registered')
        self.assertEqual(first['registration']['device_name'],'My study computer')
        self.assertEqual(first['account']['device_count'],1)
        peer=next(p for p in self.engine.snapshot()['peers'] if p['public_key']==first['device']['public_key'])
        self.assertEqual(peer['enrollment']['machine_name'],'Synthetic Win11')
        self.assertEqual(peer['enrollment']['client_version'],'0.3.0-rc18')
        self.assertIsInstance(peer['enrollment']['confirmed_at'],int)
        self.assertEqual(sum(a['action']=='device.confirmed' for a in self.engine.snapshot()['audit']),1)
        own=next(p for p in first['devices'] if p['current'])
        self.assertEqual(own['name'],'My study computer');self.assertNotIn('public_key',own)
        self.assertEqual(self.login().json()['account']['device_count'],1)

    def test_full_limit_allows_account_view_but_not_a_fourth_registration(self):
        for index in (3,5,6):self.assertEqual(self.login(index).status_code,200)
        fourth=self.login(7,confirm=False).json()
        self.assertEqual(fourth['account']['device_count'],3)
        self.assertEqual(len([p for p in fourth['devices'] if not p['revoked']]),3)
        self.assertIsNone(fourth['tunnel'])
        self.assertEqual(self.enroll(fourth['token']).json()['error'],'DEVICE_LIMIT_REACHED')
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],3)
        ClientLoginThrottle.objects.all().delete()
        self.assertEqual(self.login(3).json()['account']['device_count'],3)

    def test_legacy_login_cannot_create_or_confirm_new_device(self):
        key=base64.b64encode(bytes([3])*32).decode()
        body={'username':'client01','password':'test-only-password-012345','public_key':key,'device_name':'Old client'}
        call=lambda:self.client.post('/api/client/login',json.dumps(body),content_type='application/json',secure=True)
        self.assertEqual(call().json()['error'],'CLIENT_UPDATE_REQUIRED')
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],0)
        self.engine.dispatch({'operation':'peer.create','actor':'github:204281968','data':{'public_key':key,'user_id':self.user['id'],'name':'Already managed'}})
        self.assertEqual(call().json()['error'],'CLIENT_UPDATE_REQUIRED')
        old_token='o'*43
        import hashlib
        from datetime import timedelta
        from django.utils import timezone
        ClientSession.objects.create(account=self.account,public_key=key,token_hash=hashlib.sha256(old_token.encode()).hexdigest(),expires_at=timezone.now()+timedelta(days=1))
        old=self.state(old_token).json()
        self.assertTrue(old['device']['registered']);self.assertEqual(old['registration']['status'],'legacy')
        self.assertIsNotNone(old['tunnel'])  # keep existing sessions working during upgrade
        confirmed=self.enroll(old_token).json()
        self.assertEqual(confirmed['account']['device_count'],1)
        self.assertEqual(confirmed['registration']['status'],'registered')
        self.assertEqual(call().status_code,200)

    def test_own_device_list_and_key_ownership_never_cross_accounts(self):
        first=self.login().json()
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':{'id':None,'name':'Other private user','quota_bytes':100000,'expires_at':None,'enabled':True}})
        other=next(u for u in self.engine.snapshot()['users'] if u['id']!=self.user['id'])
        other_key=base64.b64encode(bytes([9])*32).decode()
        self.engine.dispatch({'operation':'peer.create','actor':'github:204281968','data':{'public_key':other_key,'user_id':other['id'],'name':'OTHER_PRIVATE_DEVICE'}})
        own=self.state(first['token']).json()
        self.assertNotIn('OTHER_PRIVATE_DEVICE',json.dumps(own));self.assertNotIn(other_key,json.dumps(own))
        self.assertEqual(self.login(9,confirm=False).json()['error'],'DEVICE_REVOKED')

    def test_pending_presence_cannot_claim_access_and_registered_presence_is_metadata(self):
        value=self.login(confirm=False).json();token=value['token']
        def report():return self.client.post('/api/client/presence',json.dumps({'mode':'connected','transport':'wireguard-udp'}),content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+token)
        self.assertIsNone(report().json()['tunnel'])
        self.assertEqual(ClientSession.objects.get().reported_mode,'pending')
        self.enroll(token)
        self.assertEqual(report().status_code,200)
        current=ClientSession.objects.get();self.assertEqual(current.reported_mode,'connected');self.assertEqual(current.reported_transport,'wireguard-udp');self.assertIsNotNone(current.last_seen_at)
        self.engine.dispatch({'operation':'user.put','actor':'github:204281968','data':{'id':self.user['id'],'name':'Only me','quota_bytes':0,'expires_at':None,'enabled':True}})
        self.assertEqual(report().json()['account']['status'],'quota')
        self.assertFalse(self.driver.allowed)  # reports cannot authorize traffic

    def test_administrator_sees_pending_confirmation_and_advisory_presence(self):
        from .client_api import annotate_devices
        pending=self.login(confirm=False).json();token=pending['token']
        view=annotate_devices(self.engine.snapshot())
        self.assertEqual(len(view['pending_devices']),1)
        self.assertEqual(view['pending_devices'][0]['id'],pending['registration']['device_id'])
        self.assertEqual(view['users'][0]['device_count'],0)
        self.enroll(token)
        self.client.post('/api/client/presence',json.dumps({'mode':'connected','transport':'wireguard-udp'}),content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+token)
        view=annotate_devices(self.engine.snapshot())
        self.assertEqual(view['pending_devices'],[])
        peer=next(p for p in view['peers'] if p['user_id']==self.user['id'])
        self.assertIsNotNone(peer['enrollment']['confirmed_at'])
        self.assertTrue(peer['client_status']['online'])
        self.assertEqual(peer['client_status']['reported_mode'],'connected')
        self.assertEqual(peer['client_status']['transport'],'wireguard-udp')
        self.client.post('/api/client/logout','{}',content_type='application/json',secure=True,HTTP_AUTHORIZATION='Bearer '+token)
        peer=next(p for p in annotate_devices(self.engine.snapshot())['peers'] if p['user_id']==self.user['id'])
        self.assertFalse(peer['client_status']['online'])
        self.assertIsNotNone(peer['enrollment']['confirmed_at'])

    def owner_browser(self):
        from django.contrib.auth import get_user_model
        owner=get_user_model().objects.create_user('testadmin')
        from allauth.socialaccount.models import SocialAccount
        from allauth.mfa.totp.internal.auth import TOTP
        from .tests import SECRET
        SocialAccount.objects.create(user=owner,provider='github',uid='204281968');TOTP.activate(owner,SECRET)
        browser=Client(enforce_csrf_checks=True,HTTP_HOST=HOST)
        browser.force_login(owner,backend='console.adapters.GitHubSessionBackend')
        saved=browser.session;at=time.time()
        saved['account_authentication_methods']=[{'method':'socialaccount','provider':'github','uid':'204281968','at':at},{'method':'mfa','type':'totp','at':at}];saved.save()
        import re
        page=browser.get('/',secure=True)
        token=re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"',page.content).group(1).decode()
        return browser,token

    def test_usage_history_is_administrator_only_bounded_and_read_only(self):
        token=self.login().json()['token'];path=f"/api/users/{self.user['id']}/usage"
        self.assertEqual(self.state(token,path).status_code,401)
        browser,csrf=self.owner_browser()
        for window,count in [('day',24),('week',7),('month',None)]:
            result=browser.get(path,{'window':window},secure=True);self.assertEqual(result.status_code,200)
            data=result.json();self.assertEqual(data['user_id'],self.user['id'])
            self.assertEqual(data['quota_bytes'],100000)
            if count:self.assertEqual(len(data['buckets']),count)
        self.assertEqual(browser.get(path,{'window':'year'},secure=True).status_code,400)
        self.assertEqual(browser.get(path+'?window=day&window=month',secure=True).status_code,400)
        self.assertEqual(browser.get(path,{'command':'id'},secure=True).status_code,400)
        self.assertEqual(browser.post(path,secure=True,HTTP_X_CSRFTOKEN=csrf,HTTP_ORIGIN=f'https://{HOST}').status_code,405)

    def test_administrator_delete_stops_device_frees_slot_invalidates_token_and_keeps_usage(self):
        value=self.login().json();key=value['device']['public_key'];token=value['token']
        self.driver.value['peers'][key]['tx']+=41;self.engine.tick()
        browser,csrf=self.owner_browser();body=json.dumps({'operation':'peer.delete','data':{'public_key':key}})
        self.assertEqual(browser.post('/api/control',body,content_type='application/json',secure=True).status_code,403)
        self.assertFalse(self.engine.revoked(key))
        result=browser.post('/api/control',body,content_type='application/json',secure=True,HTTP_X_CSRFTOKEN=csrf,HTTP_ORIGIN=f'https://{HOST}')
        self.assertEqual(result.status_code,200,result.content)
        self.assertFalse(any(p['public_key']==key for p in result.json()['peers']))
        self.assertNotIn(key,self.driver.value['peers']);self.assertEqual(self.engine.device_count(self.user['id']),0)
        self.assertEqual(self.state(token).status_code,401)
        self.assertFalse(ClientSession.objects.filter(public_key=key).exists())
        self.assertEqual(self.engine.used('user',self.user['id'])['tx'],41)
        self.assertEqual(self.login().json()['error'],'DEVICE_REVOKED')
        from .models import Audit
        self.assertTrue(Audit.objects.filter(action='device.deleted',resource=__import__('hashlib').sha256(key.encode()).hexdigest()[:12]).exists())

    def test_pending_device_can_be_deleted_without_ever_creating_a_peer(self):
        value=self.login(confirm=False).json();key=value['device']['public_key'];token=value['token']
        browser,csrf=self.owner_browser()
        pending=browser.get('/api/control',secure=True).json()['pending_devices'];self.assertEqual(pending[0]['public_key'],key)
        result=browser.post('/api/control',json.dumps({'operation':'peer.delete','data':{'public_key':key}}),content_type='application/json',secure=True,HTTP_X_CSRFTOKEN=csrf,HTTP_ORIGIN=f'https://{HOST}')
        self.assertEqual(result.status_code,200);self.assertEqual(result.json()['pending_devices'],[])
        self.assertEqual(self.engine.device_count(self.user['id']),0);self.assertEqual(self.state(token).status_code,401)
        self.assertEqual(self.login(confirm=False).json()['error'],'DEVICE_REVOKED')
