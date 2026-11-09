import copy
import unittest
import os
from pathlib import Path
import subprocess
import tempfile
from endpoint_catalog import ROOT
from endpoint_catalog import load,targets
from propose_endpoints import propose
from change_scope import endpoint_only

class EndpointSettingsTests(unittest.TestCase):
 def setUp(self):
  self.current={'schema':1,'revision':1,'api_host':'vpn-admin.morandi.dpdns.org','interface':'enp0s6','subnet':'10.0.0.0/24','active':'primary','primary':{'public_ipv4':'152.67.154.225','private_ipv4':'10.0.0.220'},'backup':{'public_ipv4':'150.230.113.158','private_ipv4':'10.0.0.246'},'legacy':[{'public_ipv4':'152.67.156.100','private_ipv4':'10.0.0.6'},{'public_ipv4':'141.147.78.44','private_ipv4':'10.0.0.10'}],'egress_ipv4':['152.67.156.100','152.67.154.225']}
  self.variables={'PROXY_PRIMARY_IPV4':'152.67.154.225','PROXY_PRIMARY_PRIVATE_IPV4':'10.0.0.220','PROXY_BACKUP_IPV4':'150.230.113.158','PROXY_BACKUP_PRIVATE_IPV4':'10.0.0.246'}
 def test_unchanged_does_not_propose_or_increment(self):self.assertIsNone(propose(self.current,self.variables,'prepare',True))
 def test_cutover_is_exact_swap_and_narrows_exit(self):
  self.variables['PROXY_PRIMARY_PRIVATE_IPV4']='10.0.0.6'
  value=propose(self.current,self.variables,'cutover',True)
  self.assertEqual(value['primary']['private_ipv4'],'10.0.0.6')
  self.assertEqual(next(r for r in value['legacy'] if r['public_ipv4']=='152.67.156.100')['private_ipv4'],'10.0.0.220')
  self.assertEqual(value['egress_ipv4'],['152.67.154.225'])
  self.assertEqual(value['revision'],self.current['revision']+1)
 def test_confirmation_and_public_address_guards(self):
  with self.assertRaisesRegex(ValueError,'CONFIRM_ACTUAL'):propose(self.current,self.variables,'prepare',False)
  self.variables['PROXY_PRIMARY_IPV4']='127.0.0.1'
  with self.assertRaises(ValueError):propose(self.current,self.variables,'prepare',True)
 def test_prepare_preserves_old_entry_without_silent_retirement(self):
  value=copy.deepcopy(self.current);value['primary']['private_ipv4']='10.0.0.6';value['legacy']=[];value['egress_ipv4']=['152.67.154.225']
  self.variables.update(PROXY_PRIMARY_IPV4='143.47.230.196',PROXY_PRIMARY_PRIVATE_IPV4='10.0.0.50')
  prepared=propose(value,self.variables,'prepare',True)
  self.assertEqual(prepared['legacy'],[value['primary']])
  self.assertEqual(prepared['egress_ipv4'],['152.67.154.225','143.47.230.196'])
  self.assertEqual(targets(prepared),['143.47.230.196','150.230.113.158'])
 def test_cannot_move_binding_in_prepare_or_add_address_in_cutover(self):
  self.variables['PROXY_PRIMARY_PRIVATE_IPV4']='10.0.0.6'
  with self.assertRaisesRegex(ValueError,'REQUIRES_CUTOVER'):propose(self.current,self.variables,'prepare',True)
  self.variables['PROXY_PRIMARY_IPV4']='143.47.230.196'
  with self.assertRaisesRegex(ValueError,'PREPARE_NEW_PUBLIC'):propose(self.current,self.variables,'cutover',True)
 def test_only_exact_config_requests_skip_unrelated_matrices(self):
  request={'operation':'preflight','request_id':'endpoint-catalog-apply'}
  self.assertTrue(endpoint_only(['ops/network/endpoints.json','ops/oracle-project/request.json'],request))
  for files in ([],['server/admin-oracle/console/client_api.py'],['ops/network/endpoint_catalog.py']):self.assertFalse(endpoint_only(files,request))
  self.assertFalse(endpoint_only(['ops/network/endpoints.json'],dict(request,operation='deploy')))

class SshFallbackTests(unittest.TestCase):
 def test_read_only_probe_falls_back_before_any_mutation(self):
  with tempfile.TemporaryDirectory() as directory:
   log=Path(directory)/'calls';fake=Path(directory)/'ssh'
   fake.write_text('#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nassert sys.argv[-1]=="agent-status"\ntarget=sys.argv[-2]\nwith Path(os.environ["FAKE_SSH_LOG"]).open("a") as f:f.write(target+"\\n")\nraise SystemExit(255 if target.endswith("@"+os.environ["FAIL_ENDPOINT"]) else 0)\n')
   fake.chmod(0o700)
   values=targets();result=subprocess.run(['bash','-c','source ops/network/select_ssh_endpoint.sh; select_proxy_ssh_endpoint oracle-ci agent-status "$1"; echo "$PROXY_SSH_TARGET"','fixture',str(fake)],cwd=ROOT,env={**os.environ,'FAKE_SSH_LOG':str(log),'FAIL_ENDPOINT':values[0]},text=True,capture_output=True,check=True)
   self.assertEqual(result.stdout.strip(),'oracle-ci@'+values[1])
   self.assertEqual(log.read_text().splitlines(),['oracle-ci@'+values[0],'oracle-ci@'+values[1]])

class EnvironmentDocumentationTests(unittest.TestCase):
 def test_all_current_secret_and_variable_names_are_documented(self):
  import re
  text=(ROOT/'docs/github-environments.md').read_text()
  names=set()
  for path in (ROOT/'.github/workflows').glob('*.yml'):
   names.update(re.findall(r'\b(?:secrets|vars)\.([A-Z][A-Z0-9_]+)',path.read_text()))
  self.assertTrue(names)
  self.assertEqual(sorted(name for name in names if '`'+name+'`' not in text),[])
