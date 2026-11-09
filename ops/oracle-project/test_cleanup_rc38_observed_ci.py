import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('observed_ci_test',Path(__file__).with_name('cleanup_rc38_observed_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ObservedCleanup(unittest.TestCase):
 def test_exact_two_recorded_idle_profiles_only(self):
  profiles=list(m.PROFILES.items());rows=[]
  for index,(fp,(version,begin,end)) in enumerate(profiles):rows.append({'key':str(index),'name':'runnervmabc','machine_name':'runnervmabc','client_version':version,'confirmed_at':begin+1})
  with patch.object(m,'fingerprint',side_effect=lambda key:profiles[int(key)][0] if key in ('0','1') else 'foreign'):
   self.assertEqual(m.candidates(rows+[dict(rows[0],key='foreign')],{},m.stamp(15,0,0)),['0','1'])
   with self.assertRaisesRegex(ValueError,'COMPLETED_OBSERVATION_NOT_IDLE'):m.candidates(rows,{'0':{'handshake':m.stamp(14,59,59)}},m.stamp(15,0,0))
   for field,value in [('name','Personal PC'),('machine_name','UserLaptop'),('client_version','other'),('confirmed_at',0)]:
    changed=dict(rows[0]);changed[field]=value
    with self.assertRaisesRegex(ValueError,'EXACT_LOGGED_OBSERVATION_PROFILE_REQUIRED'):m.candidates([changed],{},m.stamp(15,0,0))
   with self.assertRaisesRegex(ValueError,'EXACT_OBSERVED_CI_NOT_UNIQUE'):m.candidates(rows+[rows[0]],{},m.stamp(15,0,0))
if __name__=='__main__':unittest.main()
