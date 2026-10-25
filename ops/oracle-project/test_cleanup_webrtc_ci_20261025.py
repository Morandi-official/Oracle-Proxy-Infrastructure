import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('oct25',Path(__file__).with_name('cleanup_webrtc_ci_20261025.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
c=module.cleanup

class FixedOwnedScope(unittest.TestCase):
    def test_real_devices_other_labels_versions_times_and_active_hosts_are_excluded(self):
        row={'key':'own','name':'Cloud WebRTC acceptance','machine_name':'runnervm5a8t2','client_version':c.VERSION,'confirmed_at':c.BEGIN+1}
        rows=[row,dict(row,key='real',machine_name='METAWISEBOOK'),dict(row,key='label',name='My PC'),dict(row,key='version',client_version='other'),dict(row,key='old',confirmed_at=c.BEGIN-1),dict(row,key='future',confirmed_at=c.END+1),dict(row,key='active')]
        self.assertEqual(c.candidates(rows,{'active':{'handshake':c.END+190}},c.END+200),['own'])
        many=[dict(row,key=str(i),confirmed_at=c.BEGIN+i) for i in range(10)]
        self.assertEqual(c.candidates(many,{},c.END+1000),['0','1','2'])
        self.assertEqual(c.REQUEST,'webrtc-owned-ci-slot-release-v3-20261025')
        self.assertEqual(c.MARKER.name,'webrtc-ci-cleanup-20261025-v3.json')
