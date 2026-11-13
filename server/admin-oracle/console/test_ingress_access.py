import base64
from types import SimpleNamespace
from unittest.mock import patch
from django.test import SimpleTestCase
from . import endpoint_config,flclash

PRIMARY='152.67.154.225';BACKUP='150.230.113.158'
KEY1=base64.b64encode(bytes([1])*32).decode();KEY2=base64.b64encode(bytes([2])*32).decode()
CATALOG={'primary':{'public_ipv4':PRIMARY,'private_ipv4':'10.0.0.6'},'backup':{'public_ipv4':BACKUP,'private_ipv4':'10.0.0.246'},'revision':4,'egress_ipv4':[PRIMARY,BACKUP]}


class IngressAccessTests(SimpleTestCase):
 def test_only_authorized_entrances_are_advertised_and_preferred_is_first(self):
  state={'server_public_key':KEY1,'endpoint_public_keys':{'primary':KEY1,'backup':KEY2}}
  with patch.object(endpoint_config,'read',return_value=CATALOG):
   self.assertEqual(endpoint_config.user_catalog({},state)['addresses'],[PRIMARY])
   for access,preferred,expected in [('both','backup',[BACKUP,PRIMARY]),('backup','backup',[BACKUP])]:
    value=endpoint_config.user_catalog({'ingress':{'access':access,'preferred':preferred}},state)
    self.assertEqual(value['addresses'],expected);self.assertEqual(set(value['server_public_keys']),set(expected));self.assertEqual(value['egress_ipv4'],expected)
   with self.assertRaisesRegex(ValueError,'INGRESS_ISOLATION_NOT_READY'):
    endpoint_config.user_catalog({'ingress':{'access':'both','preferred':'primary'}},{'server_public_key':KEY1})
 def test_flclash_permission_change_keeps_same_key_and_two_stable_nodes(self):
  row=SimpleNamespace(account_id='account')
  user={'id':'account','ingress':{'access':'primary','preferred':'primary'}}
  state={'server_public_key':KEY1,'endpoint_public_keys':{'primary':KEY1,'backup':KEY2},'users':[user]}
  peer={'allowed_ips':['10.77.0.2/32']};private=base64.b64encode(bytes([3])*32).decode()
  with patch.object(endpoint_config,'read',return_value=CATALOG),patch.object(flclash,'ipv6_info',return_value=None),patch.object(flclash,'transport_address',return_value=PRIMARY):
   before=flclash.configuration(row,state,peer,private)
   user['ingress']={'access':'backup','preferred':'backup'}
   after=flclash.configuration(row,state,peer,private)
  self.assertEqual({node['server'] for node in before['proxies']},{PRIMARY,BACKUP})
  self.assertTrue(all(node['private-key']==private for node in before['proxies']+after['proxies']))
  self.assertEqual(before['proxy-groups'][0]['type'],'fallback');self.assertEqual(after['proxy-groups'][0]['proxies'][0],'备用 IP UDP')
  self.assertEqual(before['rules'],['MATCH,Proxy UDP']);self.assertEqual(after['rules'],before['rules'])

 def test_client_state_primary_only_and_switched_default_keep_logical_endpoint(self):
  from django.utils import timezone
  from .client_api import client_state
  key=base64.b64encode(bytes([4])*32).decode()
  user={'id':'account','usage':{'rx':0,'tx':0},'quota':None,'remaining_bytes':None,'expires':None,'device_limit':3,'device_count':1,'status':'active','ingress':{'access':'primary','preferred':'primary'}}
  peer={'public_key':key,'user_id':'account','name':'same device','revoked':False,'allowed_ips':['10.77.0.2/32'],'handshake':0,'usage':{'rx':0,'tx':0},'enrollment':{'confirmed_at':1}}
  snapshot={'users':[user],'peers':[peer],'observed_at':int(timezone.now().timestamp()),'period':'2026-11','error':None,'budget':{'guard_blocked':False},'listen_port':51820,'server_public_key':KEY1,'endpoint_public_keys':{'primary':KEY1,'backup':KEY2}}
  with patch.object(endpoint_config,'read',return_value=CATALOG):
   first=client_state(snapshot,SimpleNamespace(user_id='account',username='test'),key)
   self.assertNotIn('network_endpoints',first);self.assertNotIn('backup_address',first['tunnel']);self.assertEqual(first['tunnel']['transport_address'],PRIMARY)
   user['ingress']={'access':'both','preferred':'backup'}
   second=client_state(snapshot,SimpleNamespace(user_id='account',username='test'),key)
  self.assertEqual(second['tunnel']['server_public_key'],KEY2);self.assertEqual(second['tunnel']['backup_address'],PRIMARY)
  self.assertEqual(second['tunnel']['endpoint'],'152.67.156.100:51820')
  self.assertEqual(second['network_endpoints']['primary'],BACKUP)
