import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('retirement',Path(__file__).resolve().parents[1]/'oracle-project/retire_udp_return_ab.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


class RetirementTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.events=[];self.alias=True;self.foreign=False
        self.baseline={'addresses':['10.0.0.6','10.0.0.10'],'defaults':['enp0s6'],'rules':['original']}
        self.value={'schema':1,'device':'enp0s6','primary':'10.0.0.6','secondary':'10.0.0.157','public':'79.72.85.11',
                    'label':'enp0s6:opab','lease_id':'a'*32,'phase':'active','baseline':copy.deepcopy(self.baseline)}
        state=self.root/'state.json';state.write_text(json.dumps(self.value))
        script=self.root/'installed.py';script.write_bytes(b'owned script')
        (self.root/'udp_return_ab_endpoint.py').write_bytes(b'owned script')
        def write(path,body):path.write_bytes(body)
        def owned(path):
            if path.is_symlink():raise ValueError('FOREIGN_FILE')
        self.m=SimpleNamespace(DEVICE='enp0s6',STATE=state,SCRIPT=script,
            lock=lambda:os.open(self.root/'lock',os.O_CREAT|os.O_RDWR,0o600),
            load_state=lambda:copy.deepcopy(self.value),snapshot=self.snapshot,
            owned_alias=lambda a:not self.foreign,owned_file=owned,write=write,rollback_locked=self.rollback)
        self.addCleanup(patch.stopall)
        patch.object(r,'ROOT',self.root).start();patch.object(r,'RECEIPT',self.root/'receipt.json').start()
        patch.object(r,'module',return_value=self.m).start();patch.object(r.os,'geteuid',return_value=0).start()
        self.exit=patch.object(r,'exit_ipv4',return_value='152.67.156.100').start()
        patch.object(r,'stop_unit',side_effect=lambda unit:self.events.append(unit)).start()

    def snapshot(self):return copy.deepcopy(self.baseline),[{'local':'10.0.0.157'}] if self.alias else []

    def rollback(self,token):
        self.assertEqual(token,'a'*32);self.events.append('remove-only-157')
        self.alias=False;self.value['phase']='rolled_back'

    def test_exact_alias_timer_and_script_removed_protected_baseline_unchanged(self):
        before=copy.deepcopy(self.baseline);result=r.execute()
        self.assertTrue(result['cleaned']);self.assertFalse(self.alias)
        self.assertFalse(self.m.STATE.exists());self.assertFalse(self.m.SCRIPT.exists())
        self.assertEqual(self.baseline,before)
        self.assertEqual(self.events,['oracle-proxy-udp-ab-'+('a'*32)+'.timer',
                                     'oracle-proxy-udp-ab-'+('a'*32)+'.service','remove-only-157'])
        self.assertEqual(self.exit.call_count,2)
        self.assertTrue(r.execute()['cleaned'])
        self.assertEqual(self.events.count('remove-only-157'),1)

    def test_foreign_alias_refused_before_any_mutation(self):
        self.foreign=True
        with self.assertRaisesRegex(ValueError,'FOREIGN_ALIAS'):r.execute()
        self.assertEqual(self.events,[]);self.assertTrue(self.alias)

    def test_changed_original_route_refused(self):
        self.baseline['defaults']=['foreign-route']
        with self.assertRaisesRegex(ValueError,'BASELINE_CHANGED'):r.execute()
        self.assertEqual(self.events,[])

    def test_unknown_stable_script_is_not_deleted(self):
        self.m.SCRIPT.write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError,'FOREIGN_STABLE_SCRIPT'):r.execute()
        self.assertEqual(self.events,[]);self.assertTrue(self.m.SCRIPT.exists())

    def test_not_restored_primary_exit_stops_before_alias_or_timer_changes(self):
        self.exit.side_effect=ValueError('RESTORED_PRIMARY_PUBLIC_IP_REQUIRED')
        with self.assertRaisesRegex(ValueError,'RESTORED_PRIMARY'):r.execute()
        self.assertEqual(self.events,[]);self.assertTrue(self.alias)

    def test_post_cleanup_verification_failure_keeps_receipt_and_can_resume(self):
        self.exit.side_effect=['152.67.156.100',ValueError('EXIT_CHECK_FAILED')]
        with self.assertRaisesRegex(ValueError,'EXIT_CHECK_FAILED'):r.execute()
        self.assertFalse(self.alias);self.assertTrue(self.m.STATE.exists())
        self.assertFalse(json.loads(r.RECEIPT.read_text())['cleaned'])
        self.exit.side_effect=None
        self.assertTrue(r.execute()['cleaned'])


if __name__=='__main__':unittest.main()
