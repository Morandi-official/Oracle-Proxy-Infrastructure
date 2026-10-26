import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('cleanup_rc20_webrtc_ci',Path(__file__).with_name('cleanup_rc20_webrtc_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Cleanup(unittest.TestCase):
    def test_only_failed_hosted_receipt_can_release_one_slot(self):
        row={'key':'test','name':'Cloud WebRTC acceptance','machine_name':'runnervmfixture','client_version':m.cleanup.VERSION,'confirmed_at':m.cleanup.BEGIN+10}
        now=m.cleanup.END+1000
        self.assertEqual(m.candidates([row],{},now),['test'])
        for key,value in [('name','METAWISEBOOK'),('machine_name','METAWISEBOOK'),('client_version','0.3.0-rc19'),('confirmed_at',m.cleanup.END+1)]:
            self.assertEqual(m.candidates([{**row,key:value}],{},now),[])
        self.assertEqual(m.candidates([row],{'test':{'handshake':now}},now),[])
        with self.assertRaises(ValueError):m.candidates([row,row],{},now)

if __name__=='__main__':unittest.main()
