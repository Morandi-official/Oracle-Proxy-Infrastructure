import copy
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

spec=importlib.util.spec_from_file_location('policy_agent',Path(__file__).with_name('agent.py'))
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
KEY1='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
KEY2='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
KEY3='AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='


class FakeDriver:
 def __init__(self):
  self.value={'peers':{KEY1:{'allowed_ips':['10.250.0.2/32'],'rx':100,'tx':100,'handshake':0},KEY2:{'allowed_ips':['10.250.0.3/32'],'rx':200,'tx':300,'handshake':0}},'nics':{'eth0':{'rx':1000,'tx':2000}},'boot':'first','networks':['10.250.0.1/24'],'server_public_key':'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=','listen_port':51820}
  self.allowed=set();self.managed=set();self.global_allowed=False;self.fail=False
 def initialize(self,guarded): self.guarded=guarded
 def revoke(self): self.allowed=set();self.global_allowed=False
 def leases(self,managed,allowed,global_allowed): self.managed.update(managed);self.allowed=set(allowed);self.global_allowed=global_allowed
 def observe(self):
  if self.fail: raise OSError('synthetic')
  return copy.deepcopy(self.value)
 def add_peer(self,key,addresses): self.value['peers'][key]={'allowed_ips':addresses,'rx':0,'tx':0,'handshake':0}


class PolicyTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.TemporaryDirectory();self.database=Path(self.directory.name)/'state.sqlite3'
  self.clock=[1792497600];self.driver=FakeDriver();self.engine=agent.Engine(self.database,self.driver,lambda:self.clock[0]);self.engine.tick()
 def tearDown(self): self.engine.db.close();self.directory.cleanup()
 def request(self,operation,data): return self.engine.dispatch({'operation':operation,'actor':'github:204281968','data':data})
 def user(self,**kwargs):
  data={'id':None,'name':'Test user','quota_bytes':100,'expires_at':None,'enabled':True};data.update(kwargs)
  self.request('user.put',data)
  return self.engine.snapshot()['users'][-1]
 def bind(self,key,user): self.request('peer.assign',{'public_key':key,'user_id':user['id'],'name':'Test PC'})
 def budget(self,**kwargs):
  data={'limit_bytes':10000,'reserve_bytes':1000,'guard_enabled':True,'prior_usage_bytes':100,'confirm_current_period':True};data.update(kwargs);return self.request('budget.set',data)['budget']
 def test_unmanaged_peers_not_enrolled_or_restricted_by_installation(self):
  self.assertEqual(self.driver.managed,set());self.assertFalse(self.engine.get('budget')['guard_enabled'])
  self.assertEqual(len(self.engine.snapshot()['peers']),2)
  self.assertTrue(all(not p['managed'] for p in self.engine.snapshot()['peers']))
 def test_multiple_devices_share_quota_and_existing_sessions_are_blocked(self):
  user=self.user();self.bind(KEY1,user);self.bind(KEY2,user)
  self.assertEqual(self.driver.allowed,{'10.250.0.2','10.250.0.3'})
  self.driver.value['peers'][KEY1]['rx']+=40;self.driver.value['peers'][KEY2]['tx']+=60;self.engine.tick()
  self.assertEqual(self.engine.used('user',user['id']),{'rx':40,'tx':60});self.assertEqual(self.driver.allowed,set())
  self.assertEqual(self.engine.snapshot()['users'][0]['status'],'quota')
  self.user(id=user['id'],quota_bytes=1000);self.assertEqual(len(self.driver.allowed),2)
  self.assertEqual(self.engine.used('user',user['id'])['tx'],60)
 def test_expiration_and_disable_are_independent_of_web_polling(self):
  user=self.user(expires_at=self.clock[0]+2);self.bind(KEY1,user)
  self.clock[0]+=3;self.engine.tick();self.assertEqual(self.driver.allowed,set())
  self.user(id=user['id'],expires_at=None,enabled=False);self.assertEqual(self.driver.allowed,set())
  self.user(id=user['id'],expires_at=None,enabled=True);self.assertEqual(self.driver.allowed,{'10.250.0.2'})
 def test_restart_and_counter_reset_do_not_reset_accumulated_user_usage(self):
  user=self.user(quota_bytes=1000);self.bind(KEY1,user)
  self.driver.value['peers'][KEY1]['tx']+=70;self.driver.value['nics']['eth0']['tx']+=200;self.engine.tick()
  self.engine.db.close();self.engine=agent.Engine(self.database,self.driver,lambda:self.clock[0])
  self.assertEqual(self.driver.allowed,set());self.engine.tick();self.assertEqual(self.engine.used('user',user['id'])['tx'],70)
  self.driver.value['boot']='second';self.driver.value['peers'][KEY1]['tx']=10;self.driver.value['nics']['eth0']['tx']=20
  self.engine.tick();self.assertEqual(self.engine.used('user',user['id'])['tx'],80)
  self.assertEqual(self.engine.used('server','all')['tx'],220)
 def test_reassignment_does_not_transfer_or_erase_prior_user_usage(self):
  old=self.user(quota_bytes=1000);self.bind(KEY1,old);self.driver.value['peers'][KEY1]['rx']+=20
  new=self.user(name='Z user',quota_bytes=1000);self.bind(KEY1,new)
  self.driver.value['peers'][KEY1]['rx']+=30;self.engine.tick()
  self.assertEqual(self.engine.used('user',old['id'])['rx'],20);self.assertEqual(self.engine.used('user',new['id'])['rx'],30)
 def test_unknown_history_does_not_show_full_free_balance_and_guard_blocks(self):
  budget=self.engine.snapshot()['budget'];self.assertIsNone(budget['remaining_bytes']);self.assertEqual(budget['measured_outbound_bytes'],0)
  result=self.budget(prior_usage_bytes=None,confirm_current_period=False)
  self.assertTrue(result['guard_blocked']);self.assertFalse(self.driver.global_allowed)
 def test_vnic_outbound_and_user_bidirectional_counters_have_distinct_basis(self):
  self.budget();self.driver.value['nics']['eth0']['tx']+=9000;self.driver.value['nics']['eth0']['rx']+=900000
  self.driver.value['peers'][KEY1]['rx']+=100000;self.engine.tick()
  result=self.engine.budget_state();self.assertEqual(result['remaining_bytes'],900);self.assertEqual(result['vpn_available_bytes'],0)
  self.assertFalse(self.driver.global_allowed);self.assertEqual(result['measured_outbound_bytes'],9000)
 def test_budget_policy_edit_preserves_usage_until_explicit_recalibration(self):
  self.budget();self.driver.value['nics']['eth0']['tx']+=55;self.engine.tick()
  result=self.budget(limit_bytes=20000,prior_usage_bytes=None,confirm_current_period=False)
  self.assertEqual(result['estimated_used_bytes'],155)
  self.assertEqual(self.budget(prior_usage_bytes=1000)['estimated_used_bytes'],1000)
 def test_counter_gap_makes_balance_unknown_and_fails_closed_when_enabled(self):
  self.budget();self.clock[0]+=agent.LEASE+1;self.engine.tick()
  self.assertIsNone(self.engine.budget_state()['remaining_bytes']);self.assertFalse(self.driver.global_allowed)
  self.assertEqual(self.budget(prior_usage_bytes=300)['estimated_used_bytes'],300)
 def test_full_observation_across_utc_month_rollover_resets_period_not_history(self):
  self.clock[0]=1793491199;self.engine.tick();self.budget(prior_usage_bytes=1000)
  self.clock[0]+=2;self.driver.value['nics']['eth0']['tx']+=25;self.engine.tick()
  self.assertEqual(self.engine.budget_state()['current_period'],'2026-11')
  self.assertEqual(self.engine.budget_state()['estimated_used_bytes'],25)
 def test_missing_observations_do_not_renew_any_leases(self):
  user=self.user();self.bind(KEY1,user);before=self.engine.last_enforced;self.clock[0]+=1;self.driver.fail=True
  with self.assertRaises(OSError):self.engine.tick()
  self.assertEqual(self.engine.last_enforced,before);self.assertIsNotNone(self.engine.snapshot()['error'])
  self.assertEqual(self.driver.allowed,set())
 def test_partial_enforcement_failure_revokes_allowances_and_exposes_error(self):
  user=self.user();self.bind(KEY1,user)
  def partial(*args):
   self.driver.allowed={'10.250.0.2'}
   raise RuntimeError('SYNTHETIC_FIREWALL_FAILURE')
  with patch.object(self.driver,'leases',side_effect=partial):
   with self.assertRaises(RuntimeError):self.engine.enforce()
  self.assertEqual(self.driver.allowed,set());self.assertEqual(self.engine.snapshot()['error'],'ENFORCEMENT_FAILED')
 def test_automatic_access_transitions_are_audited_without_sensitive_payloads(self):
  user=self.user(expires_at=self.clock[0]+2);self.bind(KEY1,user)
  self.clock[0]+=3;self.engine.tick()
  entries=self.engine.snapshot()['audit']
  self.assertTrue(any(e['action']=='access.expired' and e['resource']==user['id'] for e in entries))
  self.assertNotIn(KEY1,str(entries))
 def test_peer_creation_allocates_free_address_and_restores_only_owned_peers(self):
  user=self.user();self.request('peer.create',{'public_key':KEY3,'user_id':user['id'],'name':'New Windows PC'})
  self.assertEqual(self.driver.value['peers'][KEY3]['allowed_ips'],['10.250.0.4/32'])
  del self.driver.value['peers'][KEY3];self.engine.tick();self.engine.tick()
  self.assertIn(KEY3,self.driver.value['peers'])
  self.assertFalse(self.engine.snapshot()['peers'][0]['public_key'].startswith('PRIVATE'))
 def test_failed_kernel_peer_creation_retains_durable_owned_policy_for_safe_retry(self):
  user=self.user()
  with patch.object(self.driver,'add_peer',side_effect=RuntimeError('SYNTHETIC_KERNEL_FAILURE')):
   with self.assertRaises(RuntimeError):self.request('peer.create',{'public_key':KEY3,'user_id':user['id'],'name':'Pending PC'})
  row=self.engine.db.execute('SELECT * FROM devices WHERE key=?',(KEY3,)).fetchone()
  self.assertEqual(row['user_id'],user['id']);self.assertEqual(row['owned'],1)
  self.assertIn('10.250.0.4',self.driver.managed);self.assertNotIn('10.250.0.4',self.driver.allowed)
  self.engine.tick();self.engine.tick()
  self.assertIn(KEY3,self.driver.value['peers']);self.assertIn('10.250.0.4',self.driver.allowed)
 def test_reject_network_peer_and_arbitrary_operation_paths_commands_and_invalid_keys(self):
  user=self.user();self.driver.value['peers'][KEY1]['allowed_ips']=['10.250.0.0/24']
  with self.assertRaises(ValueError): self.bind(KEY1,user)
  for operation in ('sh','service.restart','wg set','state;id'):
   with self.assertRaises(ValueError):self.request(operation,{})
  for key in ('../../etc/shadow',KEY1+';id','A'*44):
   with self.assertRaises(ValueError):agent.public_key(key)
  with self.assertRaises(ValueError):self.user(quota_bytes=True)
  with self.assertRaises(ValueError):self.request('budget.set',{'command':'id'})

 def test_default_cap_reassignment_and_revocation_tombstone(self):
  user=self.user(quota_bytes=100000)
  self.bind(KEY1,user);self.bind(KEY2,user)
  self.request('peer.create',{'public_key':KEY3,'user_id':user['id'],'name':'Third'})
  extra=agent.base64.b64encode(b'\x09'*32).decode()
  with self.assertRaisesRegex(ValueError,'DEVICE_LIMIT_REACHED'):
   self.request('peer.create',{'public_key':extra,'user_id':user['id'],'name':'Fourth'})
  with self.assertRaisesRegex(ValueError,'REVOKE_DEVICES_BEFORE_LOWERING_LIMIT'):
   self.request('user.limit',{'user_id':user['id'],'device_limit':2})
  self.request('peer.revoke',{'public_key':KEY1});self.assertNotIn('10.250.0.2',self.driver.allowed)
  self.request('peer.create',{'public_key':extra,'user_id':user['id'],'name':'Replacement'})
  self.assertEqual(self.engine.device_count(user['id']),3)
  with self.assertRaisesRegex(ValueError,'DEVICE_REVOKED'):self.bind(KEY1,user)
  self.engine.db.close();self.engine=agent.Engine(self.database,self.driver,lambda:self.clock[0]);self.engine.tick()
  self.assertNotIn('10.250.0.2',self.driver.allowed)
  self.assertEqual(self.engine.device_limit(user['id']),3)

if __name__=='__main__':unittest.main()
