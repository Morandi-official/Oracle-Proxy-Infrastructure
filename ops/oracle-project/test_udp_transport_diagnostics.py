import importlib.util
import json
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('udpdiag',Path(__file__).with_name('udp_transport_diagnostics.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)

class UdpSummaryTests(unittest.TestCase):
    def test_nat_counters_and_input_order_do_not_export_private_rule_data(self):
        text='''*nat
[12:2300] -A PREROUTING -p udp --dport 8443 -m u32 --u32 "0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000" -m comment --comment private-label -j REDIRECT --to-ports 51820
[99:200] -A PREROUTING -p udp --dport 443 -j REDIRECT --to-ports 51820
COMMIT
*filter
[3:4] -A INPUT -s 192.0.2.10/32 -p udp --dport 51820 -j ACCEPT
[5:6] -A INPUT -j REJECT
[7:8] -A INPUT -p udp --dport 8443 -j ACCEPT
COMMIT'''
        result=diag.firewall_summary(text)
        self.assertEqual(result['ports']['8443']['redirect_packets'],12)
        self.assertEqual(result['ports']['443']['redirect_rules'],0)
        self.assertEqual(result['ports']['8443']['input_accept_positions'],[3])
        self.assertEqual(result['unconditional_input_reject_positions'],[2])
        self.assertNotIn('192.0.2.10',json.dumps(result));self.assertNotIn('private-label',json.dumps(result))

    def test_iptables_save_hex_normalization_does_not_hide_a_valid_demux(self):
        a='0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000'
        b='0x0>>0x16&0x3c@0x8=0x1000000,0x2000000,0x3000000,0x4000000'
        self.assertEqual(diag.normalize_u32(a),diag.normalize_u32(b))
        data=diag.firewall_summary('*nat\n[42:12345] -A PREROUTING -p udp --dport 8443 -m u32 --u32 "'+b+'" -j REDIRECT --to-ports 51820\nCOMMIT')
        self.assertEqual(data['ports']['8443']['redirect_rules'],1)
        self.assertEqual(data['ports']['8443']['redirect_packets'],42)
