import importlib.util, pathlib, sys, types, unittest
P=pathlib.Path(__file__).with_name('cleanup_old_hosted_ci.py')
class Tests(unittest.TestCase):
 def setUp(self):
  self.m=types.ModuleType('bounded_old_ci'); self.m.HOSTED=r'(?:fv-az[0-9]+-[0-9]+|runnervm[a-z0-9]{1,32})'; self.m.STATE=pathlib.Path('/tmp')
  spec=importlib.util.spec_from_file_location('scope_test',P);self.x=importlib.util.module_from_spec(spec)
  from unittest.mock import patch
  with patch('importlib.util.module_from_spec',return_value=self.m),patch('importlib.util.spec_from_file_location') as loader:
   loader.return_value.loader.exec_module=lambda module:None
   exec(compile(P.read_text(),str(P),'exec'),self.x.__dict__)
  self.now=self.x.END+172800
 def row(self,**change):
  r=dict(key='peer',name='runnervma5ucf',machine_name='runnervma5ucf',client_version=next(iter(self.x.VERSIONS)),confirmed_at=self.x.BEGIN+100);r.update(change);return r
 def test_known(self):self.assertEqual(self.x.candidates([self.row()],{},self.now),['peer'])
 def test_real(self):
  for name in ['METAWISEBOOK','DESKTOP-MORANDI']:
   self.assertEqual(self.x.candidates([self.row(name=name,machine_name=name)],{},self.now),[])
 def test_renamed(self):self.assertEqual(self.x.candidates([self.row(name='My real PC')],{},self.now),[])
 def test_new_version(self):self.assertEqual(self.x.candidates([self.row(client_version='unknown')],{},self.now),[])
 def test_recent_handshake(self):self.assertEqual(self.x.candidates([self.row()],{'peer':{'handshake':self.now-60}},self.now),[])
 def test_today(self):self.assertEqual(self.x.candidates([self.row(confirmed_at=self.now-60)],{},self.now),[])
 def test_bounded(self):
  self.assertEqual(len(self.x.candidates([self.row(key=str(i)) for i in range(8)],{},self.now)),3)
if __name__=='__main__':unittest.main()
