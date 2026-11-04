import base64
import importlib.util
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.test import TestCase, Client, override_settings
from .models import ClientAccount, FlClashProfile, Audit
from . import flclash

spec=importlib.util.spec_from_file_location('flclash_policy_tests',Path(__file__).resolve().parents[1]/'control/test_agent.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)

@override_settings(ADMIN_AUTH_MODE='local',ADMIN_LOCAL_USERNAME='profile-admin',AUTHENTICATION_BACKENDS=['console.local_auth.LocalAdminBackend'])
class FlClashTests(TestCase):
 def setUp(self):
  self.directory=tempfile.TemporaryDirectory();self.driver=policy.FakeDriver();self.driver.value['networks'].append('fd42:6f70:78:77::1/64')
  self.engine=policy.agent.Engine(Path(self.directory.name)/'ledger.sqlite3',self.driver,time.time);self.engine.tick()
  self.user=self.engine.dispatch({'operation':'user.save','actor':'local:1','data':{'id':None,'name':'Profile user','quota_bytes':1000000,'expires_at':None,'enabled':True,'device_limit':3}})['users'][0]
  self.account=ClientAccount.objects.create(user_id=self.user['id'],username='profile-user',password=make_password('synthetic-pass-12'))
  get_user_model().objects.create_user(username='profile-admin',password='synthetic-admin-12',is_staff=True)
  self.client.post('/login/',{'username':'profile-admin','password':'synthetic-admin-12'},secure=True)
  self.calls=[]
  def call(op,actor,data):
   self.calls.append(op);return self.engine.dispatch({'operation':op,'actor':actor,'data':data})
  self.mock=patch('console.flclash.control.call',side_effect=call);self.mock.start()
  self.v6=patch('console.flclash.ipv6_info',return_value={'prefix':'fd42:6f70:78:77::/64'});self.v6.start()
 def tearDown(self):self.mock.stop();self.v6.stop();self.engine.db.close();self.directory.cleanup()
 def post(self,path,data):return self.client.post(path,json.dumps(data),content_type='application/json',secure=True)
 def create(self):
  return self.post('/api/flclash/create',{'user_id':self.user['id']})
 def link(self,pk):return self.post('/api/flclash/'+str(pk),{'action':'link'}).json()['url']
 def download(self,url):return self.client.get(url,secure=True)
 def test_actual_ledger_enrollment_unique_slot_encrypted_keys_and_udp_only_dualstack(self):
  created=self.create();self.assertEqual(created.status_code,201)
  row=FlClashProfile.objects.get();url=self.link(row.pk);body=self.download(url)
  self.assertEqual(body.status_code,200);data=json.loads(body.content);node=data['proxies'][0]
  self.assertEqual(node['type'],'wireguard');self.assertEqual(node['port'],443);self.assertEqual(data['rules'],['MATCH,Proxy UDP']);self.assertEqual(data['proxy-groups'],[])
  self.assertEqual(node['mtu'],1280);self.assertEqual(len(base64.b64decode(node['private-key'])),32)
  self.assertTrue(node['ipv6'].startswith('fd42:6f70:78:77:'));self.assertTrue(data['dns']['respect-rules']);self.assertTrue(data['tun']['strict-route'])
  self.assertNotIn(node['private-key'],row.encrypted_material);self.assertNotIn(url.split('/')[-2],row.encrypted_material)
  listed=self.client.get('/api/flclash',secure=True).content.decode();self.assertNotIn(node['private-key'],listed);self.assertNotIn(url,listed)
  self.assertEqual(self.engine.device_count(self.user['id']),1);self.assertEqual(body['Referrer-Policy'],'no-referrer');self.assertIn('no-store',body['Cache-Control'])
  before=self.engine.device_count(self.user['id']);self.download(url);self.download(url);self.assertEqual(self.engine.device_count(self.user['id']),before)
  self.assertFalse(Audit.objects.filter(resource__contains=node['private-key']).exists())
 def test_revoke_stops_cached_config_and_link_and_keeps_accounting(self):
  self.create();row=FlClashProfile.objects.get();url=self.link(row.pk)
  self.assertEqual(self.post('/api/flclash/'+str(row.pk),{'action':'revoke'}).status_code,200)
  self.assertEqual(self.download(url).status_code,404);row.refresh_from_db();self.assertEqual(row.encrypted_material,'');self.assertTrue(self.engine.revoked(row.public_key));self.assertEqual(self.engine.device_count(self.user['id']),0)
  self.assertTrue(any(p['public_key']==row.public_key for p in self.engine.snapshot()['peers']))
  self.assertFalse(self.driver.allowed)
 def test_two_native_devices_leave_only_one_configuration_without_pending_refusal(self):
  for key in (base64.b64encode(bytes([14])*32).decode(),base64.b64encode(bytes([15])*32).decode()):
   self.engine.dispatch({'operation':'peer.enroll','actor':'local:1','data':{'public_key':key,'user_id':self.user['id'],'name':'native','machine_name':'native','client_version':'0.3.0','confirm':True}})
  self.assertEqual(self.create().status_code,201)
  row=FlClashProfile.objects.get();self.assertEqual(row.name,'profile-user的第1个FlClash设备')
  self.assertEqual(self.create().json()['error'],'DEVICE_LIMIT_REACHED')
  self.assertEqual(FlClashProfile.objects.count(),1);self.assertEqual(self.engine.device_count(self.user['id']),3)
  self.assertEqual(self.download(self.link(row.pk)).status_code,200)
 def test_handshake_records_key_usage_without_inventing_hardware_identity(self):
  self.create();row=FlClashProfile.objects.get();state=self.engine.snapshot()
  peer=next(p for p in state['peers'] if p['public_key']==row.public_key)
  peer['handshake']=int(time.time())
  flclash.observe_usage(state);row.refresh_from_db();self.assertIsNotNone(row.last_used_at)
  self.assertTrue(peer['flclash_used'])
  peer['handshake']=0;flclash.observe_usage(state);row.refresh_from_db();self.assertIsNotNone(row.last_used_at)
  self.assertTrue(peer['flclash_used'])
 def test_disabled_quota_expiry_and_stale_control_never_download_config(self):
  self.create();row=FlClashProfile.objects.get();url=self.link(row.pk)
  self.engine.db.execute('UPDATE users SET quota=0 WHERE id=?',(self.user['id'],));self.engine.enforce()
  self.assertEqual(self.download(url).status_code,503);self.assertFalse(self.driver.allowed)
 def test_anonymous_csrf_bad_token_unconfirmed_and_invalid_account_refused(self):
  anonymous=Client();self.assertEqual(anonymous.get('/api/flclash',secure=True).status_code,401)
  self.assertEqual(anonymous.post('/api/flclash/create',{},secure=True).status_code,401)
  locked=Client(enforce_csrf_checks=True);self.assertEqual(locked.post('/api/flclash/create',{},secure=True).status_code,403)
  self.assertEqual(self.post('/api/flclash/create',{'user_id':'bad','name':'bad','confirm':True}).status_code,400)
  self.assertEqual(self.post('/api/flclash/create',{'user_id':self.user['id'],'name':'bad','confirm':False}).status_code,400)
  self.assertEqual(FlClashProfile.objects.count(),0)
  self.create();row=FlClashProfile.objects.get();url=self.link(row.pk);self.assertEqual(self.download(url.replace(url.split('/')[-2],'A'*43)).status_code,404)
  self.assertEqual(self.client.get('/api/flclash/'+str(row.pk),secure=True).status_code,405)
