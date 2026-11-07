import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('rc32_completed_cleanup',Path(__file__).with_name('cleanup_rc32_completed_ci.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ExactCompletedCiCleanup(unittest.TestCase):
    def row(self,index=0,**changes):
        profile=module.PROFILES[index]
        return {'key':'synthetic-key-'+str(index),'name':profile['machine'],'machine_name':profile['machine'],
                'client_version':profile['version'],'confirmed_at':profile['begin']+10,**changes}
    def test_only_exact_finished_identities_are_eligible(self):
        now=max(p['end'] for p in module.PROFILES)+3600
        expected=[self.row(i)['key'] for i in range(len(module.PROFILES))]
        self.assertEqual(module.candidates([self.row(i) for i in range(len(module.PROFILES))],{},now),expected)
        for changes in ({'name':'METAWISEBOOK'},{'machine_name':'METAWISEBOOK'},
                        {'client_version':'0.3.0-rc32+unrelated'},
                        {'confirmed_at':module.PROFILES[0]['begin']-1},
                        {'confirmed_at':module.PROFILES[0]['end']+1}):
            with self.subTest(changes=changes):self.assertEqual(module.candidates([self.row(**changes)],{},now),[])
        with self.assertRaises(ValueError):
            module.candidates([self.row()],{self.row()['key']:{'handshake':now-179}},now)
    def test_duplicate_matches_refuse_entire_plan(self):
        with self.assertRaises(ValueError):
            module.candidates([self.row(),self.row(key='another-synthetic-key')],{},max(p['end'] for p in module.PROFILES)+3600)

if __name__=='__main__':unittest.main()
