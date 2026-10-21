"""Read-only usage diagnostics must not export raw credential/cache fields."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('project', Path(__file__).with_name('project_operations.py'))
project = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project)


class OfficialUsageSummary(unittest.TestCase):
    def test_only_fixed_fields_leave_the_host(self):
        value = {'schema': 1, 'status': 'INSTANCE_PRINCIPAL_READY', 'vnic_outbound_bytes': 123,
                 'instance_id': 'not exported', 'compartment_id': 'not exported',
                 'unexpected_private_field': 'must not export', 'remaining_bytes': 10**13}
        with patch.object(project.Path, 'is_symlink', return_value=False), patch.object(project.Path, 'stat', return_value=SimpleNamespace(st_size=1024)), patch.object(project.Path, 'read_text', return_value=json.dumps(value)):
            result = project.official_usage_status()
        self.assertEqual(result['vnic_outbound_bytes'], 123)
        self.assertIsNone(result['remaining_bytes'])
        self.assertNotIn('not exported', json.dumps(result))
        self.assertNotIn('must not export', json.dumps(result))

    def test_only_bounded_sku_units_and_quantities_are_exported(self):
        value = {'schema': 1, 'billing_rows': [{'sku': 'Outbound Data Transfer', 'unit': 'GB',
                 'quantity': 2.5, 'unexpected_customer_field': 'SECRET'}]}
        def read(body):
            with patch.object(project.Path, 'is_symlink', return_value=False), patch.object(project.Path, 'stat', return_value=SimpleNamespace(st_size=1024)), patch.object(project.Path, 'read_text', return_value=json.dumps(body)):
                return project.official_usage_status()
        result = read(value)
        self.assertEqual(result['billing_rows'], [{'sku': 'Outbound Data Transfer', 'unit': 'GB', 'quantity': 2.5}])
        self.assertNotIn('SECRET', json.dumps(result))
        for quantity in (None, True, -1, float('inf'), 10**19):
            value['billing_rows'][0]['quantity'] = quantity
            self.assertEqual(read(value)['status'], 'CACHE_UNAVAILABLE')

    def test_missing_symlink_oversized_and_structured_fields_fail_closed(self):
        for link, size, body in ((True, 0, '{}'), (False, 32769, '{}'),
                                 (False, 10, '[]'), (False, 10, '{"schema":1,"status":{"raw":"error"}}')):
            with self.subTest(link=link, size=size, body=body), patch.object(project.Path, 'is_symlink', return_value=link), patch.object(project.Path, 'stat', return_value=SimpleNamespace(st_size=size)), patch.object(project.Path, 'read_text', return_value=body):
                self.assertEqual(project.official_usage_status()['status'], 'CACHE_UNAVAILABLE')
        with patch.object(project.Path, 'is_symlink', side_effect=OSError()):
            self.assertEqual(project.official_usage_status()['status'], 'CACHE_UNAVAILABLE')


if __name__ == '__main__': unittest.main()
