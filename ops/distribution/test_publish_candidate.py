import copy
import tempfile
import unittest
import zipfile
from pathlib import Path

from publish_candidate import REPO, read_archive, validate_run


class PublicationBoundaries(unittest.TestCase):
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
    def test_source_and_payload_metadata_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'out';out.mkdir();archive=root/'outer.zip'
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('BUILD.json','{"version":"rc6"}')
            read_archive(archive,out,'candidate')
            read_archive(archive,out,'candidate')
            with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('BUILD.json','{"version":"untrusted"}')
            with self.assertRaises(ValueError):read_archive(archive,out,'candidate')


if __name__=='__main__':unittest.main()
