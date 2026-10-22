import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('native_udp_readiness.py'))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

class NativeReadiness(unittest.TestCase):
    def test_source_port_and_source_network_restrictions_are_not_open_access(self):
        value=native.summarize_rules('''-P INPUT DROP
-A INPUT -p udp -m udp --dport 51820 -j ACCEPT
-A INPUT -s 0.0.0.0/0 -p udp -m udp --dport 51820 -j ACCEPT
-A INPUT -s 192.0.2.1/32 -p udp --dport 51820 -j ACCEPT
-A INPUT -p udp --sport 51820 --dport 51820 -j ACCEPT
-A INPUT -p udp --dport 8443 -j ACCEPT
-A INPUT -p udp --dport 51828 -j ACCEPT
-A INPUT -p tcp --dport 51820 -j ACCEPT
''',51820)
        self.assertEqual(value,{'simple_any_source_accept_rules':2,'conditional_accept_rules':2})
        self.assertNotIn('192.0.2.1',json.dumps(value))
    def test_observation_exports_only_fixed_fields(self):
        outputs=['51820\n','UNEXPORTED_SOCKET_ADDRESS\n','-A INPUT -p udp --dport 51820 -j ACCEPT\n']
        def read(args,**kwargs):return subprocess.CompletedProcess(args,0,outputs.pop(0),'')
        with patch.object(native.subprocess,'run',side_effect=read):value=native.observe()
        self.assertEqual(value['status'],'OBSERVED')
        self.assertTrue(value['udp_listener_present'])
        self.assertEqual(value['external_reachability'],'NOT_TESTED')
        self.assertNotIn('UNEXPORTED',json.dumps(value))
    def test_failures_cannot_imply_reachability(self):
        with patch.object(native.subprocess,'run',side_effect=OSError('private detail')):value=native.observe()
        self.assertEqual(value,{'status':'OBSERVATION_UNAVAILABLE','external_reachability':'NOT_TESTED'})

if __name__=='__main__':unittest.main()
