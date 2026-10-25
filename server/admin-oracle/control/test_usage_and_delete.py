"""Real ledger history and device deletion; no network or production state."""
import datetime as dt
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('history_fixture',Path(__file__).with_name('test_agent.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)


class HistoryAndDeleteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'ledger.sqlite3'
        self.clock=[int(dt.datetime(2026,10,25,10,0,tzinfo=dt.timezone.utc).timestamp())]
        self.driver=f.FakeDriver();self.engine=f.agent.Engine(self.path,self.driver,lambda:self.clock[0]);self.engine.tick()
        self.user=self.request('user.put',{'id':None,'name':'Owner','quota_bytes':1000000,'expires_at':None,'enabled':True})['users'][0]
        self.request('peer.assign',{'public_key':f.KEY1,'user_id':self.user['id'],'name':'PC'})
    def tearDown(self):self.engine.db.close();self.tmp.cleanup()
    def request(self,operation,data,actor='local:1'):
        return self.engine.dispatch({'operation':operation,'actor':actor,'data':data})
    def history(self,window='day',user=None):return self.request('usage.history',{'user_id':user or self.user['id'],'window':window})
    def traffic(self,rx,tx):
        self.clock[0]+=5;self.driver.value['peers'][f.KEY1]['rx']+=rx;self.driver.value['peers'][f.KEY1]['tx']+=tx;self.engine.tick()
    def test_real_deltas_roll_up_to_day_week_month_without_reconstructing_old_month_usage(self):
        self.engine.add_usage('user',self.user['id'],500,600)
        self.traffic(40,60)
        for window,count in [('day',24),('week',7),('month',25)]:
            data=self.history(window);self.assertEqual(len(data['buckets']),count)
            self.assertEqual(data['recorded_bytes'],100);self.assertEqual(data['month_used_bytes'],1200)
            self.assertFalse(data['history_complete'])
            self.assertTrue(any(b['coverage']=='unknown' for b in data['buckets']))
        self.assertEqual(self.engine.used('user',self.user['id']),{'rx':540,'tx':660})
        self.assertFalse(any(b['coverage']=='complete' and b['start_at']<self.engine.get('usage_hourly_started_at') for b in self.history()['buckets']))
    def test_gaps_and_counter_resets_keep_month_accounting_but_do_not_invent_hourly_timing(self):
        self.traffic(10,20);self.clock[0]+=3600;self.driver.value['peers'][f.KEY1]['tx']+=90;self.engine.tick()
        data=self.history();self.assertEqual(data['recorded_bytes'],30);self.assertEqual(data['month_used_bytes'],120)
        self.assertEqual(data['buckets'][10]['coverage'],'partial');self.assertEqual(data['buckets'][11]['coverage'],'partial')
        self.driver.value['boot']='restarted';self.driver.value['peers'][f.KEY1].update(rx=5,tx=8);self.engine.tick()
        self.assertEqual(self.history()['recorded_bytes'],30);self.assertEqual(self.history()['month_used_bytes'],133)
    def test_user_isolation_ownership_changes_and_restart_preserve_detail(self):
        self.traffic(10,15)
        second=self.request('user.put',{'id':None,'name':'Other','quota_bytes':None,'expires_at':None,'enabled':True})['users'][0]
        second=next(u for u in self.engine.snapshot()['users'] if u['id']!=self.user['id'])
        self.request('peer.assign',{'public_key':f.KEY1,'user_id':second['id'],'name':'PC'})
        self.traffic(0,7)
        self.assertEqual(self.history(user=second['id'])['recorded_bytes'],7)
        self.assertEqual(self.history()['recorded_bytes'],25)
        self.engine.db.close();self.engine=f.agent.Engine(self.path,self.driver,lambda:self.clock[0]);self.engine.tick()
        self.assertEqual(self.history()['recorded_bytes'],25)
    def test_history_read_does_not_renew_leases_and_rejects_unknown_windows_or_deleted_users(self):
        before=self.engine.last_enforced;self.clock[0]+=3;self.history();self.assertEqual(self.engine.last_enforced,before)
        for bad in ('year','../','',None):
            with self.assertRaises(ValueError):self.history(bad)
        with self.assertRaisesRegex(ValueError,'ADMINISTRATOR'):self.request('usage.history',{'user_id':self.user['id'],'window':'day'},'system:client-api')
        self.request('user.delete',{'user_id':self.user['id']})
        with self.assertRaisesRegex(ValueError,'USER_NOT_FOUND'):self.history()
    def test_delete_removes_kernel_peer_hides_record_frees_slot_and_keeps_accounting(self):
        self.traffic(12,34);data=self.request('peer.delete',{'public_key':f.KEY1})
        self.assertFalse(any(p['public_key']==f.KEY1 for p in data['peers']))
        self.assertNotIn(f.KEY1,self.driver.value['peers']);self.assertNotIn('10.250.0.2',self.driver.allowed)
        self.assertEqual(self.engine.device_count(self.user['id']),0)
        self.assertEqual(self.history()['month_used_bytes'],46);self.assertEqual(self.history()['recorded_bytes'],46)
        self.request('peer.delete',{'public_key':f.KEY1})
        self.driver.add_peer(f.KEY1,['10.250.0.2/32'])
        self.engine.db.close();self.engine=f.agent.Engine(self.path,self.driver,lambda:self.clock[0]);self.engine.tick()
        self.assertNotIn(f.KEY1,self.driver.value['peers']);self.assertIn(f.KEY1,self.engine.snapshot()['deleted_public_keys'])
        with self.assertRaisesRegex(ValueError,'DEVICE_REVOKED'):
            self.request('peer.assign',{'public_key':f.KEY1,'user_id':self.user['id'],'name':'PC'})
    def test_kernel_failure_still_revokes_and_future_tick_finishes_removal(self):
        with patch.object(self.driver,'remove_peer',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):self.request('peer.delete',{'public_key':f.KEY1})
        self.assertTrue(self.engine.revoked(f.KEY1));self.assertNotIn('10.250.0.2',self.driver.allowed)
        self.engine.tick();self.assertNotIn(f.KEY1,self.driver.value['peers'])
    def test_pending_key_delete_is_permanent_and_server_key_cannot_be_deleted(self):
        self.request('peer.delete',{'public_key':f.KEY3});self.assertTrue(self.engine.revoked(f.KEY3))
        with self.assertRaisesRegex(ValueError,'ADMINISTRATOR'):self.request('peer.delete',{'public_key':f.KEY2},'system:client-api')
        with self.assertRaisesRegex(ValueError,'CLIENT_PUBLIC_KEY_EQUALS_SERVER'):
            self.request('peer.delete',{'public_key':self.driver.value['server_public_key']})
