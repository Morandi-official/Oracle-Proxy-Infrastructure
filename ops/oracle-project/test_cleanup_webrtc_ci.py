import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('cleanup_ci',Path(__file__).with_name('cleanup_webrtc_ci.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class CleanupTests(unittest.TestCase):
 def test_only_own_time_bounded_idle_azure_devices_selected_and_bounded(self):
  row={'key':'one','name':'Cloud WebRTC acceptance','machine_name':'fv-az1234-56','client_version':c.VERSION,'confirmed_at':c.BEGIN+1}
  rows=[row,dict(row,key='real',machine_name='METAWISEBOOK'),dict(row,key='other',name='My PC'),dict(row,key='new',confirmed_at=c.END+1),dict(row,key='old',confirmed_at=c.BEGIN-1),dict(row,key='version',client_version='other'),dict(row,key='busy')]
  self.assertEqual(c.candidates(rows,{'busy':{'handshake':c.END+190}},c.END+200),['one'])
  rows=[dict(row,key=str(i),confirmed_at=c.BEGIN+i) for i in range(10)]
  self.assertEqual(c.candidates(rows,{},c.END+1000),['0','1','2'])

 def test_new_hosted_windows_names_are_supported_but_real_and_unknown_names_are_not(self):
  row={'key':'own','name':'Cloud WebRTC acceptance','machine_name':'runnervm5a8t2','client_version':c.VERSION,'confirmed_at':c.BEGIN+2}
  self.assertEqual(c.candidates([row],{},c.END+1000),['own'])
  for name in ('METAWISEBOOK','DESKTOP-1234','my-runnervm5a8t2','runnervm'):
   self.assertEqual(c.candidates([dict(row,machine_name=name)],{},c.END+1000),[])
