import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('scope_secondary',Path(__file__).with_name('cleanup_secondary_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
c=m.cleanup
class ControlScope(unittest.TestCase):
    def test_only_old_hosted_control_with_exact_label_version_time_and_idle_is_selected(self):
        row={'key':'control','name':'Cloud WebRTC acceptance','machine_name':'runnervm12345','client_version':c.VERSION,'confirmed_at':c.BEGIN+60}
        rows=[row,dict(row,key='real',machine_name='METAWISEBOOK'),dict(row,key='later',confirmed_at=c.END+1),dict(row,key='label',name='My PC'),dict(row,key='version',client_version='other'),dict(row,key='busy')]
        self.assertEqual(c.candidates(rows,{'busy':{'handshake':c.END+199}},c.END+200),['control'])
        self.assertEqual(c.END-c.BEGIN,300)
        self.assertEqual(c.MARKER.name,'webrtc-ci-cleanup-20261026-v5.json')
