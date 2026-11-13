import importlib.util
import tempfile
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('ingress_fixture',Path(__file__).with_name('test_agent.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)


class IngressPolicyTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.TemporaryDirectory();self.path=Path(self.directory.name)/'ledger.sqlite3'
  self.driver=f.FakeDriver();self.engine=f.agent.Engine(self.path,self.driver);self.engine.tick()
 def tearDown(self):self.engine.db.close();self.directory.cleanup()
 def save(self,**values):
  data={'id':None,'name':'Endpoint test','enabled':True,'quota_bytes':None,'expires_at':None,'device_limit':3,**values}
  return self.engine.dispatch({'actor':'local:1','operation':'user.save','data':data})
 def test_primary_default_and_persistence_without_resetting_quota_or_device(self):
  user=self.save()['users'][0];self.assertEqual(user['ingress'],{'access':'primary','preferred':'primary'})
  self.engine.dispatch({'actor':'local:1','operation':'peer.create','data':{'public_key':f.KEY3,'user_id':user['id'],'name':'same device'}})
  self.engine.add_usage('user',user['id'],123,456)
  result=self.save(id=user['id'],ingress_access='both',ingress_preferred='backup')['users'][0]
  self.assertEqual(result['ingress'],{'access':'both','preferred':'backup'});self.assertEqual(result['usage'],{'rx':123,'tx':456});self.assertEqual(result['device_count'],1)
  self.engine.db.close();self.engine=f.agent.Engine(self.path,self.driver);self.engine.tick()
  self.assertEqual(self.engine.snapshot()['users'][0]['ingress'],result['ingress'])
 def test_invalid_or_unprivileged_policy_does_not_write(self):
  user=self.save()['users'][0]
  for access,preferred in (('primary','backup'),('backup','primary'),('all','primary')):
   with self.assertRaisesRegex(ValueError,'INVALID_INGRESS_POLICY'):self.save(id=user['id'],ingress_access=access,ingress_preferred=preferred)
  with self.assertRaisesRegex(ValueError,'ADMINISTRATOR_REQUIRED'):
   self.engine.dispatch({'actor':'system:client-api','operation':'user.save','data':{'ingress_access':'both'}})
  self.assertEqual(self.engine.ingress_policy(user['id']),{'access':'primary','preferred':'primary'})
 def test_primary_backup_only_and_both_generate_distinct_kernel_plans(self):
  user=self.save()['users'][0]
  self.engine.dispatch({'actor':'local:1','operation':'peer.create','data':{'public_key':f.KEY3,'user_id':user['id'],'name':'same device'}})
  plans=[];self.driver.ingress_peers=lambda plan:plans.append(plan)
  for access,preferred,roles in [('primary','primary',['primary']),('backup','backup',['backup']),('both','backup',['primary','backup'])]:
   self.save(id=user['id'],ingress_access=access,ingress_preferred=preferred)
   self.assertEqual(plans[-1][0]['roles'],roles);self.assertTrue(plans[-1][0]['active'])
  self.save(id=user['id'],enabled=False);self.assertFalse(plans[-1][0]['active'])
 def test_interface_counter_reset_never_double_counts_other_entrance(self):
  user=self.save()['users'][0]
  self.engine.dispatch({'actor':'local:1','operation':'peer.assign','data':{'public_key':f.KEY1,'user_id':user['id'],'name':'counter'}})
  peer=self.driver.value['peers'][f.KEY1]
  self.driver.value['peer_samples']={'wg0:'+f.KEY1:{**peer,'public_key':f.KEY1},'wgopbackup:'+f.KEY1:{**peer,'public_key':f.KEY1,'rx':0,'tx':0}}
  self.engine.tick()
  self.driver.value['peer_samples']['wg0:'+f.KEY1].update(rx=110,tx=120)
  self.driver.value['peer_samples']['wgopbackup:'+f.KEY1].update(rx=7,tx=9)
  self.engine.tick();self.assertEqual(self.engine.used('user',user['id']),{'rx':17,'tx':29})
  self.driver.value['peer_samples']['wg0:'+f.KEY1].update(rx=0,tx=0)
  self.driver.value['peer_samples']['wgopbackup:'+f.KEY1].update(rx=10,tx=13)
  self.engine.tick();self.assertEqual(self.engine.used('user',user['id']),{'rx':20,'tx':33})
