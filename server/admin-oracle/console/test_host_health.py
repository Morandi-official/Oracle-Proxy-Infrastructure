import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from . import host_health

class HostSamplerTests(TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  for p,body in {'proc/stat':'cpu  100 0 20 800 20 0 0 0 0 0\nbtime 10\n','proc/meminfo':'MemTotal: 1000000 kB\nMemAvailable: 400000 kB\n','proc/loadavg':'1.0 2.0 3.0 1/100 2\n','proc/net/dev':'header\nheader\nens3: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\nwg0: 9999999 1 0 0 0 0 0 0 9999999 1 0 0 0 0 0 0\n','proc/net/snmp':'Tcp: CurrEstab OutSegs RetransSegs\nTcp: 5 1000 10\n'}.items():self.put(p,body)
  (self.root/'sys/class/net/ens3/device').mkdir(parents=True)
 def tearDown(self):self.tmp.cleanup()
 def put(self,p,body):
  path=self.root/p;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
 def test_deltas_exclude_tunnel_and_private_baselines(self):
  one=host_health.sample(root=self.root,now=100)
  self.assertIsNone(one['cpu_percent']);self.assertIsNone(one['network']['tx_bytes_per_second'])
  self.put('proc/stat','cpu  140 0 40 840 20 0 0 0 0 0\nbtime 10\n')
  self.put('proc/net/dev','header\nheader\nens3: 11000 20 0 1 0 0 0 0 22000 40 0 0 0 0 0 0\n')
  self.put('proc/net/snmp','Tcp: CurrEstab OutSegs RetransSegs\nTcp: 7 1200 50\n')
  two=host_health.sample(one,root=self.root,now=110)
  self.assertEqual(two['cpu_percent'],60);self.assertEqual(two['network']['tx_bytes_per_second'],2000)
  self.assertEqual(two['network']['rx_bytes_per_second'],1000);self.assertEqual(two['network']['interfaces'],['ens3'])
  self.assertEqual(two['memory_percent'],60);self.assertEqual(two['tcp_retransmit_percent'],20)
  self.assertIn('NETWORK_DROPS',{a['code'] for a in two['alerts']});self.assertNotIn('_raw',host_health.public(two))
 def test_reboot_and_counter_reset_do_not_produce_negative_or_fake_rates(self):
  one=host_health.sample(root=self.root,now=100)
  self.put('proc/stat','cpu  1 0 0 1 0 0 0 0 0 0\nbtime 20\n')
  two=host_health.sample(one,root=self.root,now=110)
  self.assertIsNone(two['cpu_percent']);self.assertIsNone(two['network']['tx_bytes_per_second'])
 def test_missing_metrics_are_unknown_and_warned(self):
  (self.root/'proc/meminfo').unlink()
  value=host_health.sample(root=self.root,now=100)
  self.assertIsNone(value['memory_percent']);self.assertIn('MEMORY_UNAVAILABLE',value['errors'])
  self.assertIn('PARTIAL_SAMPLE',{a['code'] for a in value['alerts']})
