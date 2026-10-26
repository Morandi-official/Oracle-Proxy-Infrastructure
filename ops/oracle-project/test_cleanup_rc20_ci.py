import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('cleanup_rc20_ci',Path(__file__).with_name('cleanup_rc20_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Cleanup(unittest.TestCase):
    def test_receipt_exact_host_version_time_and_inactivity_are_required(self):
        row={'key':'test','name':m.MACHINE,'machine_name':m.MACHINE,'client_version':m.cleanup.VERSION,'confirmed_at':m.cleanup.BEGIN+10}
        now=m.cleanup.END+1000
        self.assertEqual(m.candidates([row],{},now),['test'])
        for key,value in [('name','METAWISEBOOK'),('machine_name','METAWISEBOOK'),('client_version','0.3.0-rc19'),('confirmed_at',m.cleanup.BEGIN-1)]:
            self.assertEqual(m.candidates([{**row,key:value}],{},now),[])
        self.assertEqual(m.candidates([row],{'test':{'handshake':now}},now),[])
        with self.assertRaises(ValueError):m.candidates([row,row],{},now)

if __name__=='__main__':unittest.main()
