"""Billing boundaries, immutable anchors, shared rates, and fail-closed recovery."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('account_policy_fixture',Path(__file__).with_name('test_agent.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class AccountPolicyTests(f.unittest.TestCase):
 setUp=f.PolicyTests.setUp
 tearDown=f.PolicyTests.tearDown
 request=f.PolicyTests.request
 user=f.PolicyTests.user
 bind=f.PolicyTests.bind
 def test_30_day_boundary_does_not_reset_at_calendar_month_or_edit(self):
  user=self.user(quota_bytes=1000);uid=user['id'];anchor=self.clock[0]
  self.bind(f.KEY1,user);self.engine.add_usage('user',uid,300,400)
  self.clock[0]=int(dt.datetime(2026,11,1,tzinfo=dt.timezone.utc).timestamp())
  self.assertEqual(sum(self.engine.used('user',uid).values()),700)
  self.user(id=uid,name='Renamed',quota_bytes=900)
  self.assertEqual(self.engine.billing.window(uid)['assigned_at'],anchor)
  self.clock[0]=anchor+30*86400-1;self.assertEqual(sum(self.engine.used('user',uid).values()),700)
  self.clock[0]+=1;self.assertEqual(sum(self.engine.used('user',uid).values()),0)
  self.assertEqual(self.engine.billing.window(uid)['start_at'],self.clock[0])
  self.engine.add_usage('user',uid,10,20);self.engine.db.close()
  self.engine=f.agent.Engine(self.database,self.driver,lambda:self.clock[0])
  self.assertEqual(sum(self.engine.used('user',uid).values()),30)
 def test_legacy_anchor_adoption_retains_usage_and_cannot_reset(self):
  user=self.user(quota_bytes=1000);uid=user['id'];anchor=self.clock[0]-5*86400
  self.engine.add_usage('user',uid,10,20)
  self.request('user.anchor',{'user_id':uid,'assigned_at':anchor,'basis':'audit'})
  self.assertEqual(sum(self.engine.used('user',uid).values()),30)
  self.assertTrue(self.engine.billing.window(uid)['usage_estimated'])
  self.request('user.anchor',{'user_id':uid,'assigned_at':anchor,'basis':'audit'})
  with self.assertRaisesRegex(ValueError,'IMMUTABLE'):self.request('user.anchor',{'user_id':uid,'assigned_at':anchor+1,'basis':'audit'})
 def test_two_dualstack_devices_share_one_user_rate_slot_and_old_edits_preserve_it(self):
  user=self.user(quota_bytes=None,download_bps=5_000_000,upload_bps=2_000_000)
  self.bind(f.KEY1,user);self.bind(f.KEY2,user)
  self.assertEqual(len(self.driver.rate_plan),1)
  self.assertEqual(set(self.driver.rate_plan[0]['addresses']),{'10.250.0.2','10.250.0.3'})
  self.user(id=user['id'],quota_bytes=None)
  self.assertEqual(self.engine.rate(user['id'])['download_bps'],5_000_000)
  self.user(id=user['id'],download_bps=None,upload_bps=None)
  self.assertEqual(self.driver.rate_plan,[])
 def test_invalid_rates_and_system_role_cannot_edit_accounts(self):
  for rate in (True,0,99999,10_000_000_001,'1'):
   with self.assertRaises(ValueError):self.user(download_bps=rate)
  with self.assertRaisesRegex(ValueError,'ADMINISTRATOR_REQUIRED'):
   self.engine.dispatch({'actor':'system:account-sync','operation':'user.put','data':{}})

class QosTests(f.unittest.TestCase):
 def test_nested_iproute2_action_headers_cannot_hide_foreign_police_actions(self):
  spec=importlib.util.spec_from_file_location('qos_json',Path(__file__).with_name('qos.py'));qos=importlib.util.module_from_spec(spec);spec.loader.exec_module(qos)
  action={'kind':'police','index':741001,'stats':{'bytes':128}}
  for listing in ([action],{'actions':[action]},[{'total acts':1,'actions':[action]}]):
   self.assertEqual(qos.action_rows(listing),[action])
   def command(args,**kw):
    self.assertNotIn('-batch',args)
    return type('Result',(),{'stdout':json.dumps(listing),'returncode':0})()
   with f.tempfile.TemporaryDirectory() as tmp:
    with self.assertRaisesRegex(ValueError,'BANDWIDTH_FOREIGN_ACTION'):
     qos.SharedIngressController(command,Path(tmp),lambda:None).apply([{'slot':1,'download_bps':None,'upload_bps':1000000,'addresses':['10.250.0.2']}])

 def test_shared_police_action_is_referenced_by_all_addresses_and_foreign_qdisc_retained(self):
  spec=importlib.util.spec_from_file_location('qos',Path(__file__).with_name('qos.py'));qos=importlib.util.module_from_spec(spec);spec.loader.exec_module(qos)
  commands=[]
  def command(args,**kw):
   commands.append((args,kw));value=[{'root':True,'kind':'noqueue','handle':'0:'}] if 'qdisc' in args else {'actions':[]} if 'actions' in args else []
   return type('Result',(),{'stdout':json.dumps(value),'returncode':0})()
  with f.tempfile.TemporaryDirectory() as tmp:
   controller=qos.Controller(command,Path(tmp),lambda:None)
   controller.apply([{'slot':1,'download_bps':1000000,'upload_bps':1000000,'addresses':['10.250.0.2','10.250.0.3','fd42::2']}])
   batch=next(kw['input'] for args,kw in commands if '-batch' in args)
   self.assertEqual(batch.count('actions add action police index 731001'),1)
   self.assertEqual(batch.count('action police index 731001'),4)
   self.assertEqual(batch.count('classid 7a10:101 htb'),1)
  def foreign(args,**kw):return type('Result',(),{'stdout':json.dumps([{'root':True,'kind':'fq_codel','handle':'999:'}])})()
  with f.tempfile.TemporaryDirectory() as tmp:
   with self.assertRaisesRegex(ValueError,'FOREIGN_QDISC'):qos.Controller(foreign,Path(tmp),lambda:None).apply([{'slot':1}])
