"""A peer-only maintenance request cannot suppress production deployment checks."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('retirement_request', Path(__file__).with_name('ci_request.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CiRetirementRoute(unittest.TestCase):
    def test_only_exact_peer_retirement_skips_unrelated_web_and_mirror_checks(self):
        request = {'operation':'enable-https','request_id':'retire-only-rc32-completed-ci-20261107'}
        self.assertTrue(module.is_ci_retirement('enable-https',request))
        for operation in module.OPERATIONS - {'enable-https'}:
            self.assertFalse(module.is_ci_retirement(operation,request))
        for identity in ('https-rollback-test','deliver-windows-rc31-and-retire-ci-20261106',
                         'retire-only-rc32-completed-ci-20261107-extra','',None):
            self.assertFalse(module.is_ci_retirement('enable-https',dict(request,request_id=identity)))

if __name__ == '__main__':unittest.main()
