import importlib.util
import json
from pathlib import Path
import subprocess
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

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

    def test_ready_premaintenance_does_not_claim_detached_recovery_and_removes_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);script=root/'ops/primary-ip-rebind/precheck.py';script.parent.mkdir(parents=True)
            manifest=root/'ops/oracle-project/request.json';manifest.parent.mkdir()
            manifest.write_text(json.dumps({'operation':'preflight','request_id':module.REQUEST}))
            credential_paths=[]
            def inspect(address,revision,key,known):
                credential_paths.extend((key,known))
                self.assertEqual(key.stat().st_mode & 0o777,0o600)
                self.assertEqual(key.read_text(),'SYNTHETIC_SECRET\n')
                return {'address':address,'status':'AUTHENTICATED_PREFLIGHT_COMPLETE','host_key_verified':True,
                        'application_configured':True,'primary_baseline_ready':True,'secondary_alias_present':True,'expected_secondary_advertised':True}
            output=io.StringIO()
            with patch.object(module,'__file__',str(script)),patch.object(module,'inspect',inspect),patch.dict(os.environ,{
                'GITHUB_ACTIONS':'true','GITHUB_REF':'refs/heads/main','GITHUB_SHA':REVISION,'CI_KEY':'SYNTHETIC_SECRET','KNOWN_HOSTS':'SYNTHETIC_SECRET'}),contextlib.redirect_stdout(output):
                module.main()
            result=json.loads((root/'dist/primary-ip-rebind/precheck.json').read_text())
            self.assertTrue(result['premaintenance_management_ready']);self.assertFalse(result['primary_detached_management_verified'])
            self.assertFalse(result['public_mapping_change_performed']);self.assertTrue(result['credential_files_removed'])
            self.assertTrue(all(not p.exists() for p in credential_paths));self.assertNotIn('SYNTHETIC_SECRET',output.getvalue())


if __name__=='__main__':unittest.main()
