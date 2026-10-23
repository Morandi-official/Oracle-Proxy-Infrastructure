"""Pure synthetic Ethernet PCAP fixtures: no real network or WFP operations."""
import ipaddress
import struct
import unittest

from r94_pcap_triage import CaptureRefused, analyze_classic_ethernet_pcap


def packet(src="198.18.0.2", dst="198.18.0.6", port=51872,
           protocol=17, vlan=False):
    src_addr, dst_addr = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if protocol == 6:
        l4 = struct.pack("!HHIIHHHH", 40000, port, 0, 0, 5 << 12, 0, 0, 0)
    else:
        l4 = struct.pack("!HHHH", 40000, port, 8,
                         1 if src_addr.version == 6 else 0)
    if src_addr.version == 4:
        ip = (b"\x45\x00" + struct.pack("!H", 20 + len(l4)) +
              b"\x00\x01\x00\x00\x40" + bytes([protocol]) + b"\x00\x00" +
              src_addr.packed + dst_addr.packed + l4)
        ethertype = b"\x08\x00"
    else:
        ip = (b"\x60\x00\x00\x00" + struct.pack("!H", len(l4)) +
              bytes([protocol, 64]) + src_addr.packed + dst_addr.packed + l4)
        ethertype = b"\x86\xdd"
    link = b"\x00" * 12
    if vlan:
        link += b"\x81\x00\x00\x01"
    return link + ethertype + ip


def pcap(*frames):
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        header += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    return header


class R94PcapReviewTests(unittest.TestCase):
    def check(self, data, source=frozenset({"198.18.0.2"}), peer="198.18.0.6"):
        return analyze_classic_ethernet_pcap(
            data, local_source_ips=source, fixed_tunnel_endpoint=peer,
            fixed_udp_port=51872)

    def test_exact_tunnel_underlay_shape_is_not_a_wfp_pass(self):
        result = self.check(pcap(packet()))
        self.assertEqual(result.approved_tunnel_shape_packets, 1)
        self.assertEqual(result.other_outbound_ip_packets, 0)
        self.assertFalse(result.proves_wfp_failclosed)
        self.assertFalse(result.proves_real_uu_continuity)
        self.assertFalse(result.authorizes_release)
        self.assertIn("REVIEW_REQUIRED", result.verdict)

    def test_ipv4_dns_direct_is_detected(self):
        result = self.check(pcap(packet(), packet(dst="8.8.8.8", port=53)))
        self.assertEqual(result.other_outbound_ip_packets, 1)
        self.assertIn("BLOCK", result.verdict)

    def test_ipv6_dns_direct_is_detected(self):
        result = self.check(pcap(
            packet(src="2001:db8::2", dst="2001:db8::6", port=51872),
            packet(src="2001:db8::2", dst="2001:4860:4860::8888", port=53)),
            source=frozenset({"2001:db8::2"}), peer="2001:db8::6")
        self.assertEqual(result.other_outbound_ip_packets, 1)

    def test_tcp_or_wrong_udp_peer_is_not_implicitly_whitelisted(self):
        result = self.check(pcap(
            packet(protocol=6), packet(dst="198.18.0.7", port=51872)))
        self.assertEqual(result.other_outbound_ip_packets, 2)

    def test_vlan_and_inbound_do_not_trigger_false_outbound(self):
        result = self.check(pcap(
            packet(vlan=True),
            packet(src="198.18.0.6", dst="198.18.0.2")))
        self.assertEqual(result.local_ip_packets, 1)
        self.assertEqual(result.approved_tunnel_shape_packets, 1)

    def test_empty_capture_never_claims_proof(self):
        result = self.check(pcap())
        self.assertEqual(result.packets_examined, 0)
        self.assertFalse(result.proves_wfp_failclosed)

    def test_malformed_truncated_unknown_link_rejected(self):
        good = pcap(packet())
        with self.assertRaises(CaptureRefused):
            self.check(good[:-3])
        with self.assertRaises(CaptureRefused):
            self.check(good[:24] + b"\x00")
        wrong = bytearray(good)
        wrong[20:24] = struct.pack("<I", 101)
        with self.assertRaises(CaptureRefused):
            self.check(bytes(wrong))
        with self.assertRaises(CaptureRefused):
            self.check(b"not a capture at all")

    def test_fragmented_ipv4_fails_closed(self):
        bad = bytearray(packet())
        bad[14 + 6:14 + 8] = b"\x20\x00"
        with self.assertRaises(CaptureRefused):
            self.check(pcap(bytes(bad)))

    def test_4_byte_fake_udp_port_cannot_be_allowlisted(self):
        full = packet()
        # Same outer destination port as pinned WireGuard, but no full
        # UDP header: reject before treating it as a valid outer datagram.
        fake = bytearray(full[:14 + 20 + 4])
        fake[14 + 2:14 + 4] = struct.pack("!H", 24)
        with self.assertRaises(CaptureRefused):
            self.check(pcap(bytes(fake)))

    def test_inconsistent_udp_declared_length_cannot_be_allowlisted(self):
        for claimed in (0, 7, 9, 200):
            fake = bytearray(packet())
            fake[14 + 20 + 4:14 + 20 + 6] = struct.pack("!H", claimed)
            with self.assertRaises(CaptureRefused):
                self.check(pcap(bytes(fake)))

    def test_ipv6_zero_udp_checksum_rejected(self):
        fake = bytearray(packet(src="2001:db8::2", dst="2001:db8::6"))
        fake[14 + 40 + 6:14 + 40 + 8] = b"\x00\x00"
        with self.assertRaises(CaptureRefused):
            self.check(pcap(bytes(fake)), source=frozenset({"2001:db8::2"}),
                       peer="2001:db8::6")

    def test_incomplete_tcp_and_invalid_header_length_rejected(self):
        frame = bytearray(packet(protocol=6))
        short = bytearray(frame[:14 + 20 + 8])
        short[14 + 2:14 + 4] = struct.pack("!H", 28)
        with self.assertRaises(CaptureRefused):
            self.check(pcap(bytes(short)))
        bad = bytearray(frame)
        bad[14 + 20 + 12] = 0x40
        with self.assertRaises(CaptureRefused):
            self.check(pcap(bytes(bad)))

    def test_declared_source_inventory_must_be_supplied(self):
        with self.assertRaises(CaptureRefused):
            self.check(pcap(packet()), source=frozenset())
        with self.assertRaises(CaptureRefused):
            self.check(pcap(packet()), source=frozenset({"not-ip"}))

    def test_no_pcap_can_approve_real_uu_wfp_or_installer(self):
        result = self.check(pcap(packet(), packet(dst="8.8.8.8", port=443)))
        self.assertFalse(result.authorizes_release)
        self.assertFalse(result.proves_wfp_failclosed)
        self.assertFalse(result.proves_real_uu_continuity)


if __name__ == "__main__":
    unittest.main()
