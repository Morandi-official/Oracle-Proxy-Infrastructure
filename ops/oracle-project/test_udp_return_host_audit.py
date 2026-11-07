import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('udp_return_host_audit.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)


class ReturnAuditTest(unittest.TestCase):
    def test_fixed_queries_include_original_and_wireguard_ports_and_mark(self):
        commands=[];waits=[]
        def read(command):
            commands.append(command)
            if command==['wg','show','wg0','fwmark']:return '0x1234'
            self.assertEqual(command[:5],['ip','-j','-4','route','get'])
            return json.dumps([{'dev':'enp0s6','from':command[7],'prefsrc':'10.0.0.6','gateway':'PRIVATE_GATEWAY'}])
        result=audit.observe(read,lambda p:'0\n',waits.append)
        self.assertEqual(waits,[5]);self.assertEqual(len(result['routes']),6)
        for command in commands[1:]:self.assertEqual(command[-2:],['mark','0x1234'])
        self.assertEqual({r['source_port'] for r in result['routes']},{443,8443,51820})
        self.assertNotIn('PRIVATE_GATEWAY',json.dumps(result))
        self.assertEqual(result['counter_delta_5s']['tx_errors'],0)

    def test_unknown_mark_never_silently_uses_unmarked_route(self):
        def read(command):
            if command[0]!='wg':raise AssertionError('unexpected query')
            return 'PRIVATE_UNEXPECTED_VALUE'
        result=audit.observe(read,lambda p:'0',lambda _:None)
        self.assertTrue(all(r['status']=='MARK_UNAVAILABLE_ROUTE_NOT_EVALUATED' for r in result['routes']))
        self.assertNotIn('PRIVATE_UNEXPECTED_VALUE',json.dumps(result))

    def test_missing_counter_is_not_reported_as_zero_and_invalid_route_is_rejected(self):
        def missing(_):raise FileNotFoundError()
        self.assertTrue(all(v is None for v in audit.counters(missing).values()))
        for value in ('{}','[]','[null]'):
            with self.assertRaises(ValueError):audit.route_summary(value)
        result=audit.route_summary('[{"dev":"../escape","prefsrc":"SECRET","from":"SECRET"}]')
        self.assertIsNone(result[0]['device']);self.assertNotIn('SECRET',json.dumps(result))


if __name__=='__main__':unittest.main()
