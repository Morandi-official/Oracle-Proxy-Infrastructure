"""Safe readiness observations cannot imply external IPv6 acceptance."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('project', Path(__file__).with_name('project_operations.py'))
project = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project)


class Ipv6Readiness(unittest.TestCase):
    def observe(self, addresses, route, route_code=0):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, route_code if 'route' in args else 0,
                                               json.dumps(route if 'route' in args else addresses), '')
        with patch.object(project.subprocess, 'run', side_effect=run), patch.object(project.Path, 'read_text', return_value='1\n'):
            value = project.ipv6_readiness()
        self.assertEqual(calls, [['ip', '-j', '-6', 'address', 'show'],
                                 ['ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111']])
        self.assertEqual(value['external_forwarding_acceptance'], 'NOT_TESTED')
        return value

    def test_global_vnic_and_private_tunnel_are_counted_without_exporting_addresses(self):
        address = '2606:4700:1234::1'
        value = self.observe([
            {'ifname': 'ens3', 'addr_info': [{'family': 'inet6', 'local': address}]},
            {'ifname': 'wg0', 'addr_info': [{'family': 'inet6', 'local': 'fd42::1'}]},
            {'ifname': 'lo', 'addr_info': [{'family': 'inet6', 'local': '::1'}]},
        ], [{'dev': 'ens3'}])
        self.assertEqual(value['physical_global_address_count'], 1)
        self.assertEqual(value['wireguard_address_count'], 1)
        self.assertTrue(value['physical_route_present'])
        self.assertNotIn(address, json.dumps(value))

    def test_link_local_and_unreachable_or_tunnel_routes_do_not_prove_egress(self):
        for route, code in (([], 2), ([{'dev': 'wg0'}], 0)):
            value = self.observe([{'ifname': 'ens3', 'addr_info': [{'family': 'inet6', 'local': 'fe80::1'}]}], route, code)
            self.assertFalse(value['physical_route_present'])
            self.assertEqual(value['physical_global_address_count'], 0)

    def test_failed_observation_is_unknown(self):
        with patch.object(project.subprocess, 'run', side_effect=OSError('synthetic')):
            self.assertEqual(project.ipv6_readiness()['status'], 'OBSERVATION_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
