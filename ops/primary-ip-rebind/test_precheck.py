import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

spec=importlib.util.spec_from_file_location('precheck',Path(__file__).with_name('precheck.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
REVISION='a'*40


class ManagementPrecheck(unittest.TestCase):
    def test_secondary_uses_original_pinned_host_identity_and_only_fixed_preflight(self):
        for target in module.TARGETS:
            command=module.command(target,REVISION,'key','known')
            self.assertIn('StrictHostKeyChecking=yes',command)
            self.assertIn('HostKeyAlias=152.67.156.100',command)
            self.assertEqual(command[-2:],['oracle-project-ci@'+target,'preflight '+REVISION])
        for target,revision in [('198.51.100.1',REVISION),('141.147.78.44','HEAD')]:
            with self.assertRaises(ValueError):module.command(target,revision,'key','known')

    def test_response_is_allowlisted_and_errors_never_export_raw_output(self):
        state={'application_configured':True,'secondary_endpoint':{'primary_baseline_ready':True,'alias_present':True},
               'public_ingress_readiness':{'expected_advertised_address':'141.147.78.44'},'secret':'SYNTHETIC_SECRET'}
        def success(*args,**kwargs):
            self.assertEqual(kwargs['timeout'],150)
            return subprocess.CompletedProcess(args,0,json.dumps(state),'SYNTHETIC_SECRET')
        result=module.inspect('141.147.78.44',REVISION,'key','known',success)
        self.assertTrue(result['host_key_verified']);self.assertNotIn('SYNTHETIC_SECRET',json.dumps(result))
        def fail(*args,**kwargs):return subprocess.CompletedProcess(args,255,'SYNTHETIC_SECRET','SYNTHETIC_SECRET')
        result=module.inspect('141.147.78.44',REVISION,'key','known',fail)
        self.assertEqual(result['status'],'SSH_CONNECTION_OR_AUTH_FAILED');self.assertNotIn('SYNTHETIC_SECRET',json.dumps(result))


if __name__=='__main__':unittest.main()
