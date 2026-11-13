import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('verify_pair',Path(__file__).with_name('verify_ingress_egress.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class VerifyPairTests(unittest.TestCase):
 def setUp(self):
  self.catalog={'interface':'enp0s6','egress_ipv4':['152.67.154.225','150.230.113.158'],
                'primary':{'private_ipv4':'10.0.0.6','public_ipv4':'152.67.154.225'},'backup':{'private_ipv4':'10.0.0.246','public_ipv4':'150.230.113.158'}}
  self.calls=[]
 def command(self,args):
  self.calls.append(args)
  if '-S' in args:return '-N OPX_INGRESS_EGRESS\n-A OPX_INGRESS_EGRESS -m connmark --mark 0x20000000/0x20000000 -m comment --comment proxy-user-ingress-v1 -j SNAT --to-source 10.0.0.246\n-A OPX_INGRESS_EGRESS -m comment --comment proxy-user-ingress-v1 -j SNAT --to-source 10.0.0.6\n'
  if args[0]=='ip':return json.dumps([{'addr_info':[{'family':'inet','local':'10.77.0.1','prefixlen':24}]}])
  if args[0]=='curl':return 'ip='+('152.67.154.225' if '10.0.0.6' in args else '150.230.113.158')+'\n'
  return ''
 def test_checks_deployed_nat_and_real_exits_without_mutating_network(self):
  with patch.object(m,'read_catalog',return_value=self.catalog),patch.object(m,'run',side_effect=self.command):result=m.verify()
  self.assertEqual(result['backup']['verified_exit_ipv4'],'150.230.113.158')
  self.assertEqual(len([c for c in self.calls if c[0]=='curl']),2)
  self.assertTrue(all('-A' not in c and '-D' not in c and '-F' not in c for c in self.calls))
 def test_backup_must_not_silently_use_primary_exit(self):
  def wrong(args):return 'ip=152.67.154.225\n' if args[0]=='curl' else self.command(args)
  with patch.object(m,'read_catalog',return_value=self.catalog),patch.object(m,'run',side_effect=wrong):
   with self.assertRaisesRegex(ValueError,'EXIT_MISMATCH_BACKUP'):m.verify()
 def test_kernel_quoted_comment_output_has_identical_rule_semantics(self):
  def quoted(args):return self.command(args).replace('--comment proxy-user-ingress-v1','--comment "proxy-user-ingress-v1"')
  with patch.object(m,'read_catalog',return_value=self.catalog),patch.object(m,'run',side_effect=quoted):
   self.assertEqual(m.verify()['primary']['verified_exit_ipv4'],'152.67.154.225')
 def test_unexpected_nat_configuration_fails_before_network_probe(self):
  with patch.object(m,'read_catalog',return_value=self.catalog),patch.object(m,'run',return_value='-A OPX_INGRESS_EGRESS -j MASQUERADE\n'):
   with self.assertRaisesRegex(ValueError,'RULES_MISMATCH'):m.verify()
