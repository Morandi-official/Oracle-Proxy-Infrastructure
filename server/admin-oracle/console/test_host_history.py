from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from . import host_history
from .models import HostMetricMinute

class HostHistoryTests(TestCase):
 def test_weighted_samples_gaps_and_all_four_ranges(self):
  now=timezone.now().replace(second=30,microsecond=0)
  host_history.record({'cpu_percent':10,'network':{'tx_bytes_per_second':100}},now-timedelta(minutes=2))
  host_history.record({'cpu_percent':30,'network':{'tx_bytes_per_second':300}},now-timedelta(minutes=2,seconds=-10))
  host_history.record({'cpu_percent':90,'network':{}},now)
  history=host_history.series('hour',now)['history']
  point=next(p for p in history if p['at']==int((now-timedelta(minutes=2)).replace(second=0).timestamp()))
  self.assertEqual(point['cpu'],20);self.assertEqual(point['tx'],200)
  self.assertTrue(any(p['cpu'] is None for p in history));self.assertTrue(any(p['tx'] is None for p in history))
  for window in host_history.WINDOWS:
   result=host_history.series(window,now)
   self.assertEqual(result['window'],window);self.assertLessEqual(len(result['history']),170)
   self.assertEqual(result['observed_minutes'],2)
 def test_retention_only_drops_old_aggregates_and_preserves_recent_samples(self):
  now=timezone.now()
  HostMetricMinute.objects.create(at=now-timedelta(days=36),aggregates={'cpu':[1,1]})
  host_history.record({'cpu_percent':25},now)
  self.assertEqual(HostMetricMinute.objects.count(),1)
 def test_nonfinite_or_missing_metrics_do_not_become_fake_zero(self):
  now=timezone.now();host_history.record({'cpu_percent':float('nan'),'memory_percent':float('inf')},now)
  history=host_history.series('hour',now)['history']
  self.assertTrue(all(p['cpu'] is None and p['memory'] is None for p in history))
 def test_upgrade_preserves_existing_raw_history(self):
  import importlib
  from django.apps import apps
  from .models import Snapshot
  now=timezone.now().replace(second=10,microsecond=0)
  Snapshot.objects.create(observed_at=now,payload={'health':{'cpu_percent':12,'network':{'rx_bytes_per_second':1000}}})
  importlib.import_module('console.migrations.0007_hostmetricminute').seed_history(apps,None)
  row=HostMetricMinute.objects.get();self.assertEqual(row.aggregates['cpu'],[12,1]);self.assertEqual(row.aggregates['rx'],[1000,1])
