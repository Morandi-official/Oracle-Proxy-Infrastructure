import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('probe',Path(__file__).with_name('udp_resolver_probe.py'))
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class ProbeTests(unittest.TestCase):
    def test_wire_query_size_bounds_and_dns_padding(self):
        large=probe.query('example.com',1200)
        self.assertGreater(len(large)+28,1200)
        self.assertLessEqual(len(large)+28,1280)
        self.assertEqual(large[2:12],b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01')
        self.assertEqual(large[-1200:],bytes(1200))
    def test_unavailable_socket_is_bounded_and_only_fixed_categories_exported(self):
        with patch.object(probe.socket,'socket',side_effect=OSError):
            rows=probe.observe()
        self.assertEqual(len(rows),12)
        self.assertTrue(all(not row['response'] for row in rows))
        self.assertTrue(all(set(row)=={'target','cycle','kind','ipv4_bytes','response','elapsed_ms'} for row in rows))

if __name__=='__main__':unittest.main()
