import importlib.util
import json
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('udpdiag',Path(__file__).with_name('udp_transport_diagnostics.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)

class UdpSummaryTests(unittest.TestCase):
    def test_link_local_output_jump_is_distinguished_from_public_and_inverted_selector(self):
        body='''*filter
:OUTPUT ACCEPT [0:0]
[2:3] -A OUTPUT -d 169.254.0.0/16 -j private-instance-services
[4:5] -A OUTPUT ! -d 169.254.0.0/16 -j private-other
COMMIT'''
        shapes=diag.firewall_summary(body)['egress']['filter_output_shapes']
        self.assertEqual(shapes[0]['destination_scope'],'LINK_LOCAL')
        self.assertFalse(shapes[0]['destination_negated'])
        self.assertTrue(shapes[1]['destination_negated'])
        self.assertNotIn('169.254',json.dumps(shapes))
        self.assertNotIn('private-',json.dumps(shapes))
        for value,expected in ((None,'ANY'),('0.0.0.0/0','ANY'),('127.0.0.0/8','LOOPBACK'),('8.8.8.8','GLOBAL'),('10.0.0.0/8','NON_GLOBAL_OR_MIXED'),('bad','UNKNOWN')):
            self.assertEqual(diag.destination_scope(value),expected)

    def test_egress_policy_and_selector_shapes_hide_addresses_and_chain_names(self):
        text='''*filter
:OUTPUT ACCEPT [0:0]
[5:6] -A OUTPUT -d 192.0.2.9/32 -p udp --dport 8443 -j private-custom-chain
[7:8] -A OUTPUT -p udp -j DROP
COMMIT
*mangle
[2:3] -A OUTPUT -s 192.0.2.10 -j MARK --set-mark 0x20
[4:5] -A POSTROUTING -j private-other
COMMIT'''
        value=diag.firewall_summary(text)['egress']
        self.assertEqual(value['filter_output_policy'],'ACCEPT')
        self.assertEqual(value['filter_output_rule_count'],2)
        self.assertEqual(value['filter_output_shapes'][0]['target'],'CUSTOM_OR_OTHER')
        self.assertTrue(value['filter_output_shapes'][0]['destination_match'])
        self.assertEqual(value['filter_output_shapes'][1]['target'],'DROP')
        self.assertEqual(value['filter_output_shapes'][1]['packets'],7)
        self.assertEqual(value['other_tables_output_rule_count'],1)
        self.assertEqual(value['other_tables_postrouting_rule_count'],1)
        self.assertNotIn('192.0.2.',json.dumps(value));self.assertNotIn('private-',json.dumps(value))

    def test_route_summaries_show_policy_routing_without_gateway_or_customer_addresses(self):
        defaults=[{'dev':'enp0s6','gateway':'192.0.2.1','prefsrc':'192.0.2.2'}]
        rules=[{'src':'all','table':'main'},{'src':'192.0.2.3','dst':'198.51.100.0/24','table':'customer-private','fwmark':'0x10'}]
        value=diag.route_summary(defaults,rules,[[{'dev':'enp0s6','dst':'1.1.1.1','prefsrc':'192.0.2.2'}]])
        self.assertEqual(value['default_devices'],['enp0s6'])
        self.assertEqual(value['custom_table_rule_count'],1)
        self.assertEqual(value['source_selector_rule_count'],1)
        self.assertEqual(value['destination_selector_rule_count'],1)
        self.assertEqual(value['marked_rule_count'],1)
        encoded=json.dumps(value)
        for secret in ('192.0.2.','198.51.100.','customer-private','1.1.1.1'):self.assertNotIn(secret,encoded)
        self.assertEqual(diag.route_summary([{'dev':'../escape'}],[],[])['default_devices'],[])

    def test_kernel_udp_counters_do_not_export_unknown_fields(self):
        text='''Ip: Forwarding DefaultTTL
Ip: 1 64
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors PrivateExtra
Udp: 100 2 3 200 1 0 987
'''
        self.assertEqual(diag.udp_kernel_counters(text),{'InDatagrams':100,'NoPorts':2,'InErrors':3,'OutDatagrams':200,'RcvbufErrors':1,'SndbufErrors':0})
        self.assertEqual(diag.udp_kernel_counters('Udp: InErrors\nUdp: invalid'),{})

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
