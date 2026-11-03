import importlib.util
import json
import stat
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ingress_readiness', Path(__file__).with_name('ingress_readiness.py'))
ingress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingress)


class IngressReadinessTests(unittest.TestCase):
    def observe(self, *, uid=0, mode=stat.S_IFREG | 0o644, size=128,
                parent_mode=stat.S_IFDIR | 0o755, content=None, readable=True):
        calls = []
        def info(path):
            return SimpleNamespace(st_uid=0, st_mode=parent_mode) if path == ingress.STATE.parent else SimpleNamespace(st_uid=uid, st_mode=mode, st_size=size)
        def run(command, **kwargs):
            calls.append(command)
            if command[0] == 'runuser':
                return SimpleNamespace(returncode=0 if readable else 1)
            return SimpleNamespace(stdout='ActiveState=active\nSubState=exited\nUnitFileState=enabled\nNRestarts=0\nExecMainStatus=0\n')
        with patch.object(Path, 'lstat', info), patch.object(Path, 'read_text', return_value=json.dumps(ingress.EXPECTED if content is None else content)), patch.object(ingress.subprocess, 'run', side_effect=run):
            result = ingress.observe()
        return result, calls

    def test_valid_metadata_requires_actual_backend_read_access(self):
        result, calls = self.observe()
        self.assertEqual(result['expected_advertised_address'], ingress.SECONDARY)
        self.assertTrue(result['backend_readable'])
        self.assertEqual(calls[0], ['runuser', '-u', ingress.APP_USER, '--', 'test', '-r', str(ingress.STATE)])
        result, _ = self.observe(readable=False)
        self.assertEqual(result['expected_advertised_address'], ingress.PRIMARY)
        self.assertFalse(result['backend_readable'])

    def test_foreign_writable_link_large_or_unexpected_metadata_not_used(self):
        for values in ({'uid': 1000}, {'mode': stat.S_IFREG | 0o664},
                       {'mode': stat.S_IFLNK | 0o777}, {'size': 2049},
                       {'parent_mode': stat.S_IFDIR | 0o777},
                       {'content': {'transport_address': '127.0.0.1'}},
                       {'content': {**ingress.EXPECTED, 'extra': 'not exported'}}):
            with self.subTest(values=values):
                result, calls = self.observe(**values)
                self.assertEqual(result['expected_advertised_address'], ingress.PRIMARY)
                self.assertFalse(any(call[0] == 'runuser' for call in calls))
                self.assertNotIn('127.0.0.1', json.dumps(result))
                self.assertNotIn('not exported', json.dumps(result))

    def test_missing_state_preserves_primary_and_never_executes_mutation(self):
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError), patch.object(ingress.subprocess, 'run', side_effect=OSError):
            result = ingress.observe()
        self.assertEqual(result['metadata_status'], 'MISSING')
        self.assertEqual(result['expected_advertised_address'], ingress.PRIMARY)
        _, calls = self.observe()
        self.assertTrue(all(call[0] == 'runuser' and call[4:6] == ['test', '-r'] or call[:2] == ['systemctl', 'show'] for call in calls))

    def test_raw_unit_output_is_never_exported(self):
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError), patch.object(ingress.subprocess, 'run', return_value=SimpleNamespace(stdout='ActiveState=active\nUnknown=SECRET\nExecMainStatus=bad value\n')):
            result = ingress.observe()
        self.assertEqual(result['secondary_unit'], {'ActiveState': 'active'})
        self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
