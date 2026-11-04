import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('preserve_failed_review',Path(__file__).with_name('preserve_rc27_failed_review.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ReviewPreservation(unittest.TestCase):
    def snapshot(self):
        return {'id':module.ARTIFACT,'name':module.NAME,'size_in_bytes':module.SIZE,
                'digest':'sha256:'+module.SHA256,'expired':False,
                'workflow_run':{'id':module.RUN,'head_sha':module.SOURCE,'head_branch':'main',
                                'repository_id':1415273545,'head_repository_id':1415273545}}

    def test_exact_review_and_source_are_required(self):
        value=self.snapshot();module.validate(value)
        for field,replacement in (('id',1),('name','accepted-release'),('size_in_bytes',1),
                                  ('digest','sha256:'+'0'*64),('expired',True)):
            changed=copy.deepcopy(value);changed[field]=replacement
            with self.subTest(field=field),self.assertRaises(ValueError):module.validate(changed)
        for field,replacement in (('id',1),('head_sha','0'*40),('head_branch','untrusted'),
                                  ('repository_id',1),('head_repository_id',1)):
            changed=copy.deepcopy(value);changed['workflow_run'][field]=replacement
            with self.subTest(field=field),self.assertRaises(ValueError):module.validate(changed)


if __name__=='__main__':unittest.main()
