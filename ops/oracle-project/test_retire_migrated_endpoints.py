import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('retirement_test',Path(__file__).with_name('retire_migrated_endpoints.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RetirementTests(unittest.TestCase):
    def test_only_new_pair_can_admit_retirement(self):
        c={'primary':{'public_ipv4':'152.67.154.225','private_ipv4':'10.0.0.6'},'backup':{'public_ipv4':'150.230.113.158','private_ipv4':'10.0.0.246'},'active':'primary','legacy':[],'revision':3}
        m.validate_catalog(c)
        for key,value in [('legacy',[{'private_ipv4':'10.0.0.10'}]),('active','backup'),('revision',2),('primary',{'public_ipv4':'152.67.156.100','private_ipv4':'10.0.0.6'}),('backup',None)]:
            bad=copy.deepcopy(c);bad[key]=value
            with self.assertRaisesRegex(ValueError,'EXACT_MIGRATED_CATALOG_REQUIRED'):m.validate_catalog(bad)

    def test_live_baseline_retains_new_pair_ipv6_and_foreign_addresses(self):
        rows=[{'local':'10.0.0.6','family':'inet','label':'enp0s6','prefixlen':24}, {'local':'10.0.0.246','family':'inet','label':'enp0s6:opmb','prefixlen':32},{'local':'2603:c020:c015:8100::10','family':'inet6','prefixlen':128}, {'local':'10.0.0.10','family':'inet','prefixlen':32}, {'local':'10.0.0.220','family':'inet','prefixlen':32}, {'local':'10.0.0.99','family':'inet','prefixlen':32}]
        def command(args):return json.dumps([{'addr_info':rows}]) if 'address' in args else json.dumps([{'dst':'default','dev':'enp0s6','expires':100}])
        with patch.object(m,'run',side_effect=command):baseline=m.baseline()
        self.assertEqual({r['local'] for r in baseline['addresses']},{'10.0.0.6','10.0.0.246','2603:c020:c015:8100::10','10.0.0.99'})
        self.assertNotIn('expires',baseline['routes'][0][0])
        rows[1]['label']='foreign'
        with patch.object(m,'run',side_effect=command),self.assertRaisesRegex(ValueError,'CURRENT_BACKUP_ALIAS_REQUIRED'):m.baseline()

    def test_primary_exit_must_be_verified_before_retirement(self):
        with patch.object(m,'run',return_value='ip=152.67.154.225\n'):m.verify_exit()
        for body in ['ip=152.67.156.100\n','ip=150.230.113.158\n','invalid']:
            with patch.object(m,'run',return_value=body),self.assertRaisesRegex(ValueError,'CURRENT_PRIMARY_EGRESS_REQUIRED'):m.verify_exit()

    def test_ra_lifetime_change_does_not_hide_route_change(self):
        self.assertEqual(m.normalized([{'gateway':'a','expires':9}]),m.normalized([{'gateway':'a','expires':8}]))
        self.assertNotEqual(m.normalized([{'gateway':'a','expires':9}]),m.normalized([{'gateway':'b','expires':8}]))

if __name__=='__main__':unittest.main()
