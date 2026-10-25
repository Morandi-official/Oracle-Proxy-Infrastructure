import importlib.util
import ipaddress
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('native_packets', Path(__file__).with_name('native_udp_packets.py'))
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def packet(source=35000, destination=51820, kind=1, length=156, ihl=20):
    body = bytearray(ihl + 12)
    body[0] = (4 << 4) | (ihl // 4);body[9] = 17
    body[12:16] = ipaddress.ip_address('192.0.2.7').packed
    body[16:20] = ipaddress.ip_address('198.51.100.8').packed
    struct.pack_into('!HHH', body, ihl, source, destination, length)
    struct.pack_into('<I', body, ihl + 8, kind)
    return body


class PacketCounts(unittest.TestCase):
    def test_directions_alias_native_and_control_are_separate(self):
        self.assertEqual(module.classify(packet(), False), ('51820', 'in_initiation'))
        self.assertEqual(module.classify(packet(destination=443), False), ('443', 'in_initiation'))
        self.assertEqual(module.classify(packet(source=443, destination=35000, kind=2, length=100), True), ('443', 'out_response'))
        self.assertEqual(module.classify(packet(destination=8443), False), ('8443', 'in_initiation'))
        self.assertEqual(module.classify(packet(destination=8443,kind=0xc3), False), ('8443', 'in_other'))

    def test_rejects_truncation_fragments_unknown_ports_and_wrong_protocol(self):
        for length in range(32): self.assertIsNone(module.classify(packet()[:length], False))
        p=packet();p[6:8]=b'\x00\x01';self.assertIsNone(module.classify(p,False))
        p=packet();p[9]=6;self.assertIsNone(module.classify(p,False))
        self.assertIsNone(module.classify(packet(destination=22),False))
        self.assertIsNone(module.classify(packet(source=35000,destination=443),True))

    def test_type_and_length_are_both_required(self):
        self.assertEqual(module.classify(packet(length=100),False),('51820','in_other'))
        self.assertEqual(module.classify(packet(kind=3,length=72),False),('51820','in_cookie'))
        self.assertEqual(module.classify(packet(kind=4,length=40),False),('51820','in_data'))
        self.assertEqual(module.classify(packet(ihl=24),False),('51820','in_initiation'))

    def test_summary_has_only_bounded_port_type_counts(self):
        import json
        self.assertEqual(module.observe.__defaults__,(300,))
        self.assertEqual(module.MAX_SECONDS,900)
        counts=module.empty();module.increment(counts,module.classify(packet(),False))
        text=json.dumps(counts)
        self.assertNotIn('192.0.2.7',text);self.assertNotIn('198.51.100.8',text)
        self.assertEqual(counts['51820']['in_initiation'],1)
        for invalid in (0,module.MAX_SECONDS+1,True,-1,'60'):
            with self.assertRaises(ValueError):module.observe(invalid)
