import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('policy',Path(__file__).with_name('prepare-tcp-policy.py'))
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
class PolicyPatchTests(unittest.TestCase):
    def test_unknown_dependency_is_refused(self):
        with self.assertRaises(ValueError):policy.patched(b'unreviewed dependency source')
    def test_only_the_unique_reviewed_stack_location_changes(self):
        body=b'package wireguard\n'+policy.ANCHOR.encode()+b'// preserve addresses and routes\n'
        with patch.object(policy,'PREIMAGE',hashlib.sha256(body).hexdigest()):
            actual=policy.patched(body)
        self.assertEqual(actual.replace(policy.PATCH.encode(),b'',1),body)
        self.assertIn(b'CongestionControlOption("cubic")',actual)
        self.assertNotIn(b'MTU',policy.PATCH.encode())
        for malformed in (b'no anchor',body+policy.ANCHOR.encode()):
            with patch.object(policy,'PREIMAGE',hashlib.sha256(malformed).hexdigest()),self.assertRaises(ValueError):policy.patched(malformed)
if __name__=='__main__':unittest.main()
