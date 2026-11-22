import json
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import endpoint_switch


class EndpointSwitchTests(unittest.TestCase):
    def setUp(self):
        catalog = endpoint_switch.catalog_module()
        storage = self.enterContext(tempfile.TemporaryDirectory())
        catalog.SELECTION_DIR = Path(storage)
        catalog.PATH = Path(storage) / 'base.json'
        primary = {'public_ipv4': '152.67.154.225', 'private_ipv4': '10.0.0.6'}
        backup = {'public_ipv4': '150.230.113.158', 'private_ipv4': '10.0.0.246'}
        self.base = {
            'schema': 1, 'revision': 7, 'api_host': 'vpn-admin.morandi.dpdns.org',
            'interface': 'enp0s6', 'subnet': '10.0.0.0/24', 'active': 'primary',
            'primary': primary, 'backup': backup,
            'egress_ipv4': [primary['public_ipv4'], backup['public_ipv4']],
            'legacy': [{'public_ipv4': '152.67.156.100', 'private_ipv4': '10.0.0.220'},
                       {'public_ipv4': '141.147.78.44', 'private_ipv4': '10.0.0.10'}],
        }
        catalog.PATH.write_text(json.dumps(self.base))
        catalog.selection_lock = nullcontext
        catalog._read_file = lambda path: json.loads(path.read_text()) if path.exists() else None
        self.catalog = catalog
        self.controller = Mock()
        self.controller.configure.side_effect = lambda value: [value[role]['private_ipv4'] for role in ('primary', 'backup')]
        self.enterContext(patch.object(endpoint_switch, 'catalog_module', return_value=catalog))
        self.probe = self.enterContext(patch.object(endpoint_switch, 'prove_mapping', return_value=True))
        self.verify = self.enterContext(patch.object(endpoint_switch, 'verify_kernel'))

    def request(self, primary='141.147.78.44', backup='150.230.113.158'):
        return {'primary': primary, 'backup': backup, 'version': self.catalog.version(self.catalog.read())}

    def test_repeated_switches_persist_with_matching_returned_version(self):
        first_request = self.request()
        first = endpoint_switch.apply(self.controller, first_request)
        self.assertEqual(first['primary']['private_ipv4'], '10.0.0.10')
        self.assertEqual(first['version'], self.catalog.version(self.catalog.read()))
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_CATALOG_STALE'):
            endpoint_switch.apply(self.controller, first_request)
        second_request = self.request('152.67.156.100', '141.147.78.44')
        second = endpoint_switch.apply(self.controller, second_request)
        self.assertEqual(second['revision'], 9)
        self.assertEqual(second['version'], self.catalog.version(self.catalog.read()))
        self.verify.assert_called_with(self.controller, self.catalog.read())
        self.assertFalse(endpoint_switch.apply(self.controller, self.request('152.67.156.100', '141.147.78.44'))['changed'])
        updated = dict(self.base, revision=8)
        self.catalog.PATH.write_text(json.dumps(updated))
        self.assertEqual(self.catalog.read(), updated)

    def test_unenrolled_address_and_failed_probe_leave_kernel_untouched(self):
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_NOT_IN_CATALOG'):
            endpoint_switch.apply(self.controller, self.request('1.1.1.1'))
        self.probe.return_value = False
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_BINDING_NOT_VERIFIED'):
            endpoint_switch.apply(self.controller, self.request())
        self.controller.ensure.assert_not_called()
        self.assertEqual(self.catalog.read(), self.base)

    def test_failed_kernel_readback_restores_previous_roles(self):
        active = endpoint_switch.apply(self.controller, self.request())
        self.verify.side_effect = [ValueError('TEST_READBACK'), None]
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_SWITCH_ROLLED_BACK'):
            endpoint_switch.apply(self.controller, self.request('152.67.156.100', '141.147.78.44'))
        self.controller.ensure.assert_called_with('10.0.0.246')
        self.verify.assert_called_with(self.controller, self.catalog.read())
        self.assertEqual(self.catalog.version(self.catalog.read()), active['version'])

    def test_failed_rollback_marks_kernel_not_ready(self):
        self.verify.side_effect = ValueError('TEST_READBACK')
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_ROLLBACK_UNVERIFIED'):
            endpoint_switch.apply(self.controller, self.request())
        self.assertFalse(self.controller.ready)
        self.assertEqual(self.catalog.read(), self.base)
