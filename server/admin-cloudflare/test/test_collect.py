import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('collect', Path(__file__).parents[1] / 'collect.py')
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)
BASE = 'ORACLE_READONLY_AGENT=OK\nWG0_SERVICE=ACTIVE\nWG0_INTERFACE=PRESENT\nUDP51820=LISTENING\n'


class CollectorTests(unittest.TestCase):
    def test_accepts_actual_agent_output(self):
        raw = 'AGENT_DEPLOYED_SHA=' + 'a' * 40 + '\n' + BASE
        self.assertEqual(collect.parse_diagnostics(raw)['WG0_SERVICE'], 'ACTIVE')

    def test_rejects_partial_duplicate_unknown_and_oversized_output(self):
        for raw in [BASE.replace('WG0_SERVICE=ACTIVE\n', ''), BASE + 'WG0_SERVICE=ACTIVE\n',
                    BASE + 'PRIVATE_KEY=secret\n', BASE.replace('=ACTIVE', '=UNKNOWN'), 'x' * 8193]:
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                collect.parse_diagnostics(raw)


if __name__ == '__main__':
    unittest.main()
