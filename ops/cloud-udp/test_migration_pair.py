import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]/'oracle-project'
class PairTest(unittest.TestCase):
 def test_both_allocations_and_safe_apply_and_rollback(self):
  for role,private,public,label in [('primary','10.0.0.220','152.67.154.225','enp0s6:opmp'),('backup','10.0.0.246','150.230.113.158','enp0s6:opmb')]:
   with self.subTest(role=role),tempfile.TemporaryDirectory() as td:
    spec=importlib.util.spec_from_file_location(role,ROOT/f'migration_{role}_endpoint.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    self.assertEqual(m.SECONDARY,private);self.assertEqual(m.PUBLIC,public);self.assertEqual(m.LABEL,label)
    self.assertEqual(json.loads(m.ALLOCATION.read_text()),m.EXPECTED_ALLOCATION)
    events=[];alias=[];baseline={'original':['10.0.0.6','10.0.0.10']};saved={}
    def run(argv):
     events.append(argv)
     if argv[:4]==['ip','-4','address','add']:alias.append({'local':private,'prefixlen':32,'label':label})
     if argv[:4]==['ip','-4','address','del']:alias.clear()
    def persist(value):saved.clear();saved.update(json.loads(json.dumps(value)))
    with patch.object(m,'STATE',Path(td)/'state'),patch.object(m,'snapshot',side_effect=lambda:(baseline,list(alias))),patch.object(m,'allocation_source',return_value='OWNER'),patch.object(m,'metadata',return_value=[]),patch.object(m,'persist',side_effect=persist),patch.object(m,'load_state',side_effect=lambda:saved.copy()),patch.object(m,'run',side_effect=run),patch.object(m,'address_rows',side_effect=lambda:list(alias)):
     m.apply_locked();self.assertEqual(saved['phase'],'active')
     self.assertEqual(events[0][0],'systemd-run');self.assertIn(f'oracle-proxy-migrate-{role}-',events[0][3])
     m.rollback_locked(saved['lease_id']);self.assertFalse(alias)
     deletes=[x for x in events if x[:4]==['ip','-4','address','del']];self.assertEqual(deletes,[['ip','-4','address','del',private+'/32','dev','enp0s6']])
 def test_foreign_alias_and_unconfirmed_allocation_refused(self):
  for role in ('primary','backup'):
   spec=importlib.util.spec_from_file_location(role,ROOT/f'migration_{role}_endpoint.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
   with patch.object(m,'snapshot',return_value=({},[])),patch.object(m,'metadata',return_value=[]),patch.object(m,'allocation_source',return_value=None),patch.object(m,'run') as command:
    with self.assertRaisesRegex(ValueError,'ALLOCATION_NOT_VERIFIED'):m.apply_locked()
    command.assert_not_called()
   with patch.object(m,'load_state',return_value={'lease_id':'a'*32}),patch.object(m,'address_rows',return_value=[{'local':m.SECONDARY,'label':'foreign','prefixlen':32}]),patch.object(m,'run') as command:
    with self.assertRaisesRegex(ValueError,'FOREIGN_ALIAS'):m.rollback_locked('a'*32)
    command.assert_not_called()
if __name__=='__main__':unittest.main()
