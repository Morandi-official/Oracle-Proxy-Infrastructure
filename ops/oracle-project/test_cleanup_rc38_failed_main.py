import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('rc38_cleanup_test',Path(__file__).with_name('cleanup_rc38_failed_main.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class OwnedCleanup(unittest.TestCase):
    def setUp(self):self.row={'key':'owned','name':'runnervmabc','machine_name':'runnervmabc','client_version':m.VERSION,'confirmed_at':m.BEGIN+10}
    def test_only_exact_recorded_idle_identity_matches(self):
        with patch.object(m,'fingerprint',side_effect=lambda key:'3fb26101d5c7' if key=='owned' else 'foreign'):
            foreign=dict(self.row,key='foreign')
            self.assertEqual(m.candidates([self.row,foreign],{},m.END+600),['owned'])
            for field,value in [('name','Personal PC'),('machine_name','My-PC'),('client_version','other'),('confirmed_at',m.BEGIN-1)]:
                changed=copy.deepcopy(self.row);changed[field]=value
                with self.assertRaisesRegex(ValueError,'EXACT_LOGGED_CI_PROFILE_REQUIRED'):m.candidates([changed],{},m.END+600)
            with self.assertRaisesRegex(ValueError,'COMPLETED_CI_NOT_IDLE'):m.candidates([self.row],{'owned':{'handshake':m.END+599}},m.END+600)
            with self.assertRaisesRegex(ValueError,'EXACT_CI_NOT_UNIQUE'):m.candidates([self.row,self.row],{},m.END+600)
if __name__=='__main__':unittest.main()
