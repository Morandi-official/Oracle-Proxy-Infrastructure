import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ipv6_egress', Path(__file__).with_name('ipv6_egress.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Probe(unittest.TestCase):
    def test_only_source_matching_ipv6_over_verified_https_proves_egress(self):
        for body, code, expected in [
            ('ip=' + probe.SOURCE + '\n', 0, 'VERIFIED'),
            ('ip=152.67.156.100\n', 0, 'UNAVAILABLE'),
            ('ip=2603:c020:c015:8100::11\n', 0, 'UNAVAILABLE'),
            ('ip=' + probe.SOURCE, 60, 'UNAVAILABLE'),
            ('not a trace', 0, 'UNAVAILABLE')]:
            with patch.object(probe.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, body, '')) as run:
                result = probe.observe()
            self.assertEqual(result['status'], expected)
            args = run.call_args.args[0]
            self.assertIn('-6', args)
            self.assertIn('--interface', args)
            self.assertNotIn('-k', args)
            self.assertNotIn('--insecure', args)
            self.assertFalse(result['tunnel_forwarding_tested'])

    def test_deadline_and_missing_tool_are_unavailable(self):
        for error in [OSError(), subprocess.TimeoutExpired('curl', 12)]:
            with patch.object(probe.subprocess, 'run', side_effect=error):
                self.assertEqual(probe.observe()['status'], 'UNAVAILABLE')

if __name__ == '__main__':
    unittest.main()
