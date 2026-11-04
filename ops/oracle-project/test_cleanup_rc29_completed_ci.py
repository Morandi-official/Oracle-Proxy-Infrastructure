import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('rc29_completed_cleanup',Path(__file__).with_name('cleanup_rc29_completed_ci.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ExactCompletedCiCleanup(unittest.TestCase):
    def row(self,**changes):
        return {'key':'synthetic-key','name':module.MACHINE,'machine_name':module.MACHINE,
                'client_version':module.VERSION,'confirmed_at':module.cleanup.BEGIN+10,**changes}

    def test_only_exact_completed_record_is_eligible(self):
        now=module.cleanup.END+3600
        self.assertEqual(module.candidates([self.row()],{'synthetic-key':{'handshake':now-181}},now),['synthetic-key'])
        for changes in ({'name':'METAWISEBOOK'},{'machine_name':'METAWISEBOOK'},
                        {'name':'another-runner'},{'client_version':'0.3.0-rc29+unrelated'},
                        {'confirmed_at':module.cleanup.BEGIN-1},{'confirmed_at':module.cleanup.END+1}):
            with self.subTest(changes=changes):
                self.assertEqual(module.candidates([self.row(**changes)],{},now),[])
        self.assertEqual(module.candidates([self.row()],{'synthetic-key':{'handshake':now-179}},now),[])

    def test_duplicate_record_refuses_entire_plan(self):
        with self.assertRaises(ValueError):
            module.candidates([self.row(),self.row(key='another-synthetic-key')],{},module.cleanup.END+3600)


if __name__=='__main__':unittest.main()
