import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('extras',Path(__file__).with_name('cleanup_extra_ips.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
COMP='ocid1.tenancy.oc1..test'

class CleanupExtrasTest(unittest.TestCase):
 def setUp(self):
  self.rows={};self.deleted=[];self.private=True
  for key,(ip,p) in {**c.ORIGINAL,**c.EXTRAS}.items():
   self.rows[key]={'id':key,'ip-address':ip,'private-ip-id':p,'lifetime':'RESERVED','compartment-id':COMP,
                   'lifecycle-state':'ASSIGNED' if p else 'AVAILABLE'}
  self.baseline={k:copy.deepcopy(self.rows[k]) for k in c.ORIGINAL}
  self.addCleanup(patch.stopall)
  patch.object(c.api,'cli',side_effect=self.cli).start()
  patch.object(c.api,'invoke',side_effect=self.invoke).start()
 def cli(self,args,request_id=None):
  if args[0]=='list':return {'data':copy.deepcopy(list(self.rows.values()))}
  key=args[args.index('--public-ip-id')+1]
  self.assertNotIn(key,c.ORIGINAL)
  if args[0]=='get':
   if key not in self.rows:raise c.api.CliError('NotAuthorizedOrNotFound',404)
   return {'data':copy.deepcopy(self.rows[key])}
  if args[0]=='delete':self.deleted.append(key);self.rows.pop(key);return {}
  raise AssertionError(args)
 def invoke(self,args,request_id=None):
  self.assertEqual(args[:2],['network','private-ip'])
  if args[2]=='get':
   self.assertEqual(args[4],c.PRIVATE157)
   if not self.private:raise c.api.CliError('NotAuthorizedOrNotFound',404)
   return {'data':{'id':c.PRIVATE157,'ip-address':'10.0.0.157','vnic-id':c.VNIC,'is-primary':False}}
  if args[2]=='delete':self.private=False;self.deleted.append(c.PRIVATE157);return {}
  if args[2]=='list':return {'data':[{'ip-address':'10.0.0.6'},{'ip-address':'10.0.0.10'}]}
  raise AssertionError(args)
 def test_only_exact_extras_and_auxiliary_private_removed_idempotently(self):
  result=c.execute(COMP,True)
  self.assertTrue(result['cleaned']);self.assertEqual(self.rows,self.baseline)
  self.assertEqual(set(self.deleted),set(c.EXTRAS)|{c.PRIVATE157})
  self.assertTrue(c.execute(COMP,True)['cleaned'])
  self.assertEqual(len(self.deleted),3)
 def test_read_only_does_not_delete(self):
  self.assertEqual(c.execute(COMP)['scope'],'READ_ONLY');self.assertEqual(self.deleted,[])
 def test_crossed_primary_binding_refuses_before_deleting_any_extra(self):
  self.rows[next(iter(c.ORIGINAL))]['private-ip-id']=c.PRIVATE157
  with self.assertRaisesRegex(c.api.Stop,'RESTORED_ORIGINAL'):c.execute(COMP,True)
  self.assertEqual(self.deleted,[])
 def test_foreign_binding_on79_refuses_before_any_delete(self):
  key=next(k for k,v in c.EXTRAS.items() if v[0]=='79.72.85.11');self.rows[key]['private-ip-id']='foreign'
  with self.assertRaisesRegex(c.api.Stop,'EXACT_EXTRA'):c.execute(COMP,True)
  self.assertEqual(self.deleted,[])
 def test_unknown_additional_resource_blocks_deletion(self):
  self.rows['foreign']={'id':'foreign','compartment-id':COMP,'lifetime':'RESERVED'}
  with self.assertRaisesRegex(c.api.Stop,'UNEXPECTED'):c.execute(COMP,True)
  self.assertEqual(self.deleted,[])
if __name__=='__main__':unittest.main()
