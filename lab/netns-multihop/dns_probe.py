#!/usr/bin/env python3
"""Minimal nonrecursive DNS responder/client for an isolated CI wg0 network.
No OS resolver configuration, Internet DNS or persistent daemon involved.
"""
import ipaddress
import socket
import struct
import sys

HOST = "10.200.250.2"
NAME = b"\x03lab\x07invalid\x00"
A = ipaddress.IPv4Address("203.0.113.53").packed
AAAA = ipaddress.IPv6Address("2001:db8::53").packed


def query_packet(qtype: int, txid: int) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + NAME + struct.pack("!HH", qtype, 1)


def expected_response(request: bytes) -> bytes:
    if len(request) != 12 + len(NAME) + 4 or request[12:12 + len(NAME)] != NAME:
        raise ValueError("Unexpected DNS question")
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", request[:12])
    qtype, qclass = struct.unpack("!HH", request[-4:])
    if flags != 0x0100 or (qd, an, ns, ar) != (1, 0, 0, 0) or qclass != 1:
        raise ValueError("Malformed DNS request")
    rdata = {1: A, 28: AAAA}.get(qtype)
    if rdata is None:
        raise ValueError("Only fixed A and AAAA supported")
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(rdata)) + rdata
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + request[12:] + answer


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, 53))
        s.settimeout(10)
        for _ in range(2):
            data, peer = s.recvfrom(512)
            s.sendto(expected_response(data), peer)


def query() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        for typ, txid in ((1, 0x1331), (28, 0x1332)):
            request = query_packet(typ, txid)
            s.sendto(request, (HOST, 53))
            response, peer = s.recvfrom(512)
            if peer != (HOST, 53) or response != expected_response(request):
                raise RuntimeError("Unexpected DNS response")
    print("DNS_TUNNEL_PASS: fixed synthetic A and AAAA records via inner UDP/53")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("serve", "query"):
        raise SystemExit("Expected serve|query")
    (serve if sys.argv[1] == "serve" else query)()
