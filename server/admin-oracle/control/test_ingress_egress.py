import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('ingress_egress',Path(__file__).with_name('ingress.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class EgressRulesTests(unittest.TestCase):
 def command(self,args,**kw):
  self.calls.append((args,kw))
  value=json.dumps([{'addr_info':[{'family':'inet','local':ip} for ip in self.locals]}]) if args[0]=='ip' else self.chain if '-S' in args else ''
  return subprocess.CompletedProcess(args,0,value,'')
 def setUp(self):self.calls=[];self.locals=['10.0.0.6','10.0.0.246'];self.chain='-N OPX_INGRESS_EGRESS\n'
 def apply(self):
  with tempfile.TemporaryDirectory() as folder:
   controller=m.Controller(self.command,Path(folder));controller.primary_address='10.0.0.6';controller.ipv4_egress('10.77.0.0/24','enp0s6','10.0.0.246')
 def test_both_ingresses_have_exact_sources_and_remove_only_owned_legacy_masquerade(self):
  self.apply();body=next(kw['input'] for args,kw in self.calls if args[0]=='iptables-restore')
  self.assertIn('--mark '+m.MARK,body);self.assertIn('--to-source 10.0.0.246',body);self.assertIn('--to-source 10.0.0.6',body)
  deletions=[args for args,kw in self.calls if '-D' in args]
  self.assertEqual(len(deletions),1);self.assertIn(m.COMMENT,deletions[0]);self.assertEqual(deletions[0][-1],'MASQUERADE')
 def test_nonlocal_source_is_rejected_before_any_firewall_write(self):
  self.locals=['10.0.0.6']
  with self.assertRaisesRegex(ValueError,'PRIVATE_ADDRESS_NOT_LOCAL'):self.apply()
  self.assertEqual(len(self.calls),1)
 def test_foreign_chain_is_preserved(self):
  self.chain='-A OPX_INGRESS_EGRESS -j ACCEPT\n'
  with self.assertRaisesRegex(ValueError,'FOREIGN_FIREWALL_CHAIN'):self.apply()
  self.assertFalse(any(args[0]=='iptables-restore' for args,kw in self.calls))
