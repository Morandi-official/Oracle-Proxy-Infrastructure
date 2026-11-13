import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('endpoint_addresses',Path(__file__).with_name('endpoint_addresses.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RouteSnapshotTests(unittest.TestCase):
 def snapshot(self,expires=100,gateway='fe80::1',rule_table=196):
  rows=[[{'dst':'default','gateway':'10.0.0.1','dev':'eth0','metric':100}],[{'dst':'default','gateway':gateway,'dev':'eth0','metric':100,'pref':'medium','expires':expires}],[{'priority':19600,'fwmark':'0x20000000','table':rule_table}]]
  with patch.object(m,'run',side_effect=[json.dumps(r) for r in rows]):return m.routes()
 def test_ra_countdown_is_not_a_route_change(self):self.assertEqual(self.snapshot(100),self.snapshot(99))
 def test_gateway_and_policy_changes_still_fail_snapshot_equality(self):
  baseline=self.snapshot()
  self.assertNotEqual(baseline,self.snapshot(gateway='fe80::2'));self.assertNotEqual(baseline,self.snapshot(rule_table=197))
