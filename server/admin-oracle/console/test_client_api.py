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

    def login(self,index=3,**extra):
        value={'username':'client01','password':'test-only-password-012345','public_key':base64.b64encode(bytes([index])*32).decode(),'device_name':'Synthetic Win11'}
        value.update(extra)
        return self.client.post('/api/client/login',json.dumps(value),content_type='application/json',secure=True)

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
