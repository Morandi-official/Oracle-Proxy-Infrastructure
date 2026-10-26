import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('scope_rc19',Path(__file__).with_name('cleanup_rc19_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Rc19Scope(unittest.TestCase):
    def test_only_exact_terminated_device_version_receipt_and_idle_state_are_selected(self):
        row={'key':'owned','name':m.MACHINE,'machine_name':m.MACHINE,'client_version':m.cleanup.VERSION,'confirmed_at':m.cleanup.BEGIN+5}
        rows=[row,dict(row,key='real',name='METAWISEBOOK',machine_name='METAWISEBOOK'),
              dict(row,key='name',name='Cloud WebRTC acceptance'),dict(row,key='machine',machine_name='other'),
              dict(row,key='version',client_version='0.3.0-rc18'),dict(row,key='later',confirmed_at=m.cleanup.END+1),dict(row,key='busy')]
        self.assertEqual(m.candidates(rows,{'busy':{'handshake':m.cleanup.END+199}},m.cleanup.END+200),['owned'])
        self.assertEqual(m.cleanup.END-m.cleanup.BEGIN,35)
        with self.assertRaisesRegex(ValueError,'NOT_UNIQUE'):m.candidates([row,dict(row,key='second')],{},m.cleanup.END+200)
