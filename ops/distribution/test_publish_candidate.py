import copy
import tempfile
import unittest
import zipfile
from pathlib import Path

from publish_candidate import REPO, read_archive, validate_run, validate_manifest, validate_dotnet_runtime


class PublicationBoundaries(unittest.TestCase):
    def runtime_metadata(self):
        return {'dotnet_sdk': '10.0.403', 'dotnet_runtime': {
            'target_framework': 'net10.0', 'deployment': 'self-contained',
            'version': '10.0.14', 'runtimeconfig_sha256': 'a'*64,
            'included_frameworks': [
                {'name': 'Microsoft.NETCore.App', 'version': '10.0.14'},
                {'name': 'Microsoft.WindowsDesktop.App', 'version': '10.0.14'}]}}

    def test_runtime_metadata_requires_actual_exact_rc22_sdk_and_runtime(self):
        metadata = self.runtime_metadata()
        validate_dotnet_runtime(metadata)
        reversed_frameworks = copy.deepcopy(metadata)
        reversed_frameworks['dotnet_runtime']['included_frameworks'].reverse()
        validate_dotnet_runtime(reversed_frameworks)
        for sdk in (None, '8.0.426', '10.0.402', '10.0.404', '10.0.403-preview.1'):
            candidate = copy.deepcopy(metadata); candidate['dotnet_sdk'] = sdk
            with self.subTest(sdk=sdk), self.assertRaises(ValueError):
                validate_dotnet_runtime(candidate)
        for runtime in (None, {}, '10.0.14', {'target_framework': 'net10.0'}):
            candidate = copy.deepcopy(metadata); candidate['dotnet_runtime'] = runtime
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                validate_dotnet_runtime(candidate)
        for field, value in [('target_framework', 'net8.0'), ('deployment', 'framework-dependent'),
                             ('version', '8.0.32'), ('version', '10.0.13'), ('version', '10.0.15'),
                             ('runtimeconfig_sha256', 'A'*64), ('runtimeconfig_sha256', 'a'*63),
                             ('runtimeconfig_sha256', None)]:
            candidate = copy.deepcopy(metadata); candidate['dotnet_runtime'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_dotnet_runtime(candidate)
        candidate = copy.deepcopy(metadata)
        candidate['dotnet_runtime']['frameworks'] = candidate['dotnet_runtime']['included_frameworks']
        with self.assertRaises(ValueError): validate_dotnet_runtime(candidate)

    def test_runtime_metadata_rejects_missing_duplicate_wrong_or_shared_frameworks(self):
        valid = self.runtime_metadata()
        frameworks = valid['dotnet_runtime']['included_frameworks']
        variants = [None, {}, [], frameworks[:1], frameworks*2, [frameworks[0], frameworks[0]],
                    [frameworks[0], {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.14'}],
                    [frameworks[0], {'name': 'Microsoft.WindowsDesktop.App', 'version': '10.0.13'}],
                    [frameworks[0], {'name': 'Microsoft.WindowsDesktop.App', 'version': '10.0.14', 'rollForward': 'LatestPatch'}],
                    [frameworks[0], 'Microsoft.WindowsDesktop.App/10.0.14'],
                    [frameworks[0], {'name': ['Microsoft.WindowsDesktop.App'], 'version': '10.0.14'}]]
        for value in variants:
            candidate = copy.deepcopy(valid); candidate['dotnet_runtime']['included_frameworks'] = value
            with self.subTest(frameworks=value), self.assertRaises(ValueError):
                validate_dotnet_runtime(candidate)

    def test_manifest_requires_two_distinct_exact_artifacts_and_rc22_source(self):
        manifest={'version':'0.3.0-rc22','run_id':42,'source_revision':'a'*40,
                  'artifacts':[{'id':1,'sha256':'b'*64},{'id':2,'sha256':'c'*64}]}
        validate_manifest(manifest)
        variants=[dict(manifest,artifacts=[]),dict(manifest,artifacts=manifest['artifacts'][:1]),
                  dict(manifest,artifacts=manifest['artifacts']*2),dict(manifest,artifacts=[manifest['artifacts'][0]]*2),
                  dict(manifest,source_revision='main'),dict(manifest,run_id=True),dict(manifest,version='0.3.0-rc9')]
        for field,value in [('id','1'),('id',0),('sha256','b'*63),('sha256','untrusted/path')]:
            candidate=copy.deepcopy(manifest);candidate['artifacts'][0][field]=value;variants.append(candidate)
        for candidate in variants:
            with self.subTest(candidate=candidate),self.assertRaises(ValueError):validate_manifest(candidate)
    def test_requires_exact_accepted_main_push_and_repository(self):
        manifest={'run_id':42,'source_revision':'a'*40}
        run={'id':42,'head_sha':'a'*40,'head_branch':'main','event':'push','status':'completed',
             'conclusion':'success','path':'.github/workflows/windows-product-candidate.yml',
             'head_repository':{'full_name':REPO}}
        validate_run(run,manifest)
        for field,value in [('id',43),('head_sha','b'*40),('head_branch','untrusted'),('event','pull_request'),
                            ('status','in_progress'),('conclusion','failure'),('path','.github/workflows/other.yml'),
                            ('head_repository',{'full_name':'attacker/repo'})]:
            candidate=copy.deepcopy(run);candidate[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError): validate_run(candidate,manifest)
    def test_flat_allowlist_rejects_executable_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'out';out.mkdir();archive=root/'outer.zip'
            for name in ('../outside','payload.exe','sub/BUILD.json'):
                with zipfile.ZipFile(archive,'w') as bundle: bundle.writestr(name,b'untrusted')
                with self.subTest(name=name),self.assertRaises(ValueError):read_archive(archive,out,'candidate')
            with zipfile.ZipFile(archive,'w') as bundle:
                entry=zipfile.ZipInfo('BUILD.json');entry.external_attr=(0o120777<<16);bundle.writestr(entry,'/etc/passwd')
            with self.assertRaises(ValueError):read_archive(archive,out,'candidate')
    def test_exact_setup_is_allowed_but_unrelated_executables_are_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'out';out.mkdir();archive=root/'outer.zip'
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('candidate-setup.exe',b'MZfixture')
            read_archive(archive,out,'candidate')
            self.assertEqual((out/'candidate-setup.exe').read_bytes(),b'MZfixture')
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('other-setup.exe',b'MZfixture')
            with self.assertRaises(ValueError):read_archive(archive,out,'candidate')

    def test_source_and_payload_metadata_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'out';out.mkdir();archive=root/'outer.zip'
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('BUILD.json','{"version":"rc6"}')
            read_archive(archive,out,'candidate')
            read_archive(archive,out,'candidate')
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('BUILD.json','{"version":"untrusted"}')
            with self.assertRaises(ValueError):read_archive(archive,out,'candidate')


if __name__=='__main__':unittest.main()
