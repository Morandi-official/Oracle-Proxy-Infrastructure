"""R94 read-only bounded classic Ethernet PCAP leak triage, not WFP proof.

Inputs are UNTRUSTED capture bytes and declared interface/source info. Never
execute pcap content, touch OS packet filters, open a socket or authorize VPN.
Only emits counts/verdicts, not addresses, payloads or remote identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct

MAX_CAPTURE_BYTES = 12_000_000
MAX_PACKETS = 20_000


class CaptureRefused(ValueError):
    pass


@dataclass(frozen=True)
class TraceReview:
    packets_examined: int
    local_ip_packets: int
    approved_tunnel_shape_packets: int
    other_outbound_ip_packets: int

    @property
    def verdict(self) -> str:
        if self.other_outbound_ip_packets:
            return "R94_POTENTIAL_PLAINTEXT_BYPASS_PACKET_FOUND_BLOCK"
        return "R94_SUPPLIED_TRACE_ONLY_EXTERNAL_WFP_REVIEW_REQUIRED"

    @property
    def proves_wfp_failclosed(self) -> bool:
        return False

    @property
    def proves_real_uu_continuity(self) -> bool:
        return False

    @property
    def authorizes_release(self) -> bool:
        return False


def analyze_classic_ethernet_pcap(
    data: bytes, *, local_source_ips: frozenset[str],
    fixed_tunnel_endpoint: str, fixed_udp_port: int,
) -> TraceReview:
    """Classify directly observed outgoing IP packets against ONE narrow peer.

    An allowed packet shape (UDP to fixed peer) is NOT proof of WireGuard
    encryption, process identity, packet capture completeness or policy.
    Source-IP inventory and capture origin require separate outside witness.
    """
    if not isinstance(data, bytes) or not 24 <= len(data) <= MAX_CAPTURE_BYTES:
        raise CaptureRefused("capture absent or exceeds fixed memory budget")
    if not isinstance(local_source_ips, frozenset) or not local_source_ips:
        raise CaptureRefused("explicit local interface source inventory required")
    if type(fixed_udp_port) is not int or not 1 <= fixed_udp_port <= 65535:
        raise CaptureRefused("fixed UDP port invalid")
    try:
        sources = {ipaddress.ip_address(s) for s in local_source_ips}
        peer = ipaddress.ip_address(fixed_tunnel_endpoint)
    except ValueError as exc:
        raise CaptureRefused("invalid independent interface/peer address") from exc
    if any(s.is_multicast or s.is_unspecified for s in sources) or (
            peer.is_multicast or peer.is_unspecified):
        raise CaptureRefused("unsafe capture source/endpoint")
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise CaptureRefused("only classic microsecond Ethernet PCAP supported")
    version_major, version_minor, _, _, snap, link = struct.unpack_from(
        endian + "HHIIII", data, 4)
    if (version_major, version_minor) != (2, 4) or snap < 64 or (
            snap > 262144) or link != 1:
        raise CaptureRefused("unsupported PCAP version/snaplen/link layer")
    pos = 24
    total = local = eligible = other = 0
    while pos < len(data):
        if len(data) - pos < 16:
            raise CaptureRefused("truncated pcap record header")
        _, _, incl, orig = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        total += 1
        if total > MAX_PACKETS or incl > snap or incl > orig or incl < 14:
            raise CaptureRefused("invalid or unbounded packet")
        if pos + incl > len(data):
            raise CaptureRefused("truncated packet payload")
        frame = memoryview(data)[pos:pos + incl]
        pos += incl
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        off = 14
        if ethertype == 0x8100:
            if len(frame) < 18:
                raise CaptureRefused("truncated vlan header")
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            off = 18
        if ethertype == 0x0800:
            if len(frame) < off + 20 or frame[off] >> 4 != 4:
                raise CaptureRefused("invalid ipv4")
            ihl = (frame[off] & 15) * 4
            if ihl < 20 or len(frame) < off + ihl:
                raise CaptureRefused("invalid ipv4 header length")
            length = struct.unpack_from("!H", frame, off + 2)[0]
            if length < ihl or len(frame) < off + length:
                raise CaptureRefused("truncated ipv4 datagram")
            source = ipaddress.IPv4Address(bytes(frame[off + 12:off + 16]))
            destination = ipaddress.IPv4Address(bytes(frame[off + 16:off + 20]))
            frag = struct.unpack_from("!H", frame, off + 6)[0]
            if frag & 0x3fff:
                raise CaptureRefused("fragmented ipv4 ambiguous for leak review")
            proto = frame[off + 9]
            transport_offset = off + ihl
            transport_end = off + length
        elif ethertype == 0x86DD:
            if len(frame) < off + 40 or frame[off] >> 4 != 6:
                raise CaptureRefused("invalid ipv6")
            payload_len = struct.unpack_from("!H", frame, off + 4)[0]
            if len(frame) < off + 40 + payload_len:
                raise CaptureRefused("truncated ipv6 datagram")
            source = ipaddress.IPv6Address(bytes(frame[off + 8:off + 24]))
            destination = ipaddress.IPv6Address(bytes(frame[off + 24:off + 40]))
            proto = frame[off + 6]
            transport_offset = off + 40
            transport_end = off + 40 + payload_len
        else:
            continue
        if source not in sources:
            continue
        local += 1
        destport = None
        if proto in (6, 17):
            if transport_end < transport_offset + 4:
                raise CaptureRefused("missing TCP/UDP port header")
            destport = struct.unpack_from("!H", frame, transport_offset + 2)[0]
        # Only the exact UDP peer shape is eligible. All other outgoing IP
        # includes DNS/53, DoT/853, TCP, IPv6 bypass, ICMP or unknown protocol.
        if proto == 17 and destination == peer and destport == fixed_udp_port:
            eligible += 1
        else:
            other += 1
    if pos != len(data):
        raise CaptureRefused("trailing unparsed capture bytes")
    return TraceReview(total, local, eligible, other)
