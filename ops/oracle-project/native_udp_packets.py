"""Bounded passive counts on the physical IPv4 interface, without packet/IP logs.

The kernel BPF filter copies only IP/UDP headers and the four-byte transport
message type, never WireGuard handshake keys or application payloads. Counts
are not proof of authentication. No routes/firewall/services are changed.
"""
import ctypes
import json
import socket
import struct
import subprocess
import time

PORTS = (51820, 443, 8443)
DEFAULT_SECONDS = 300
MAX_SECONDS = 900
FILTER = (
    (0x30, 0, 0, 0), (0x54, 0, 0, 0xf0), (0x15, 0, 13, 0x40),
    (0x30, 0, 0, 9), (0x15, 0, 11, 17),
    (0x28, 0, 0, 6), (0x45, 9, 0, 0x1fff), (0xb1, 0, 0, 0),
    (0x48, 0, 0, 2),
    (0x15, 7, 0, 51820), (0x15, 6, 0, 443), (0x15, 5, 0, 8443),
    (0x48, 0, 0, 0),
    (0x15, 3, 0, 51820), (0x15, 2, 0, 443), (0x15, 1, 0, 8443),
    (0x06, 0, 0, 0), (0x87, 0, 0, 0), (0x04, 0, 0, 12), (0x16, 0, 0, 0),
)


class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('instructions', ctypes.POINTER(Filter))]


def attach(sock):
    instructions = (Filter * len(FILTER))(*(Filter(*row) for row in FILTER))
    program = Program(len(FILTER), instructions)
    sock.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # SO_ATTACH_FILTER


def classify(header, outgoing):
    if len(header) < 20 or header[0] >> 4 != 4 or header[9] != 17:
        return None
    ihl = (header[0] & 15) * 4
    if ihl < 20 or len(header) < ihl + 12 or struct.unpack_from('!H', header, 6)[0] & 0x1fff:
        return None
    source, destination, length = struct.unpack_from('!HHH', header, ihl)
    port = source if outgoing else destination
    if port not in PORTS or length < 12:
        return None
    kind = 'other'
    value = struct.unpack_from('<I', header, ihl + 8)[0]
    if value == 1 and length == 156: kind = 'initiation'
    elif value == 2 and length == 100: kind = 'response'
    elif value == 3 and length == 72: kind = 'cookie'
    elif value == 4 and length >= 40: kind = 'data'
    return str(port), ('out_' if outgoing else 'in_') + kind


def empty():
    return {str(port): {} for port in PORTS}


def increment(counts, item):
    if item:
        port, key = item
        counts[port][key] = counts[port].get(key, 0) + 1


def physical_interface():
    value = subprocess.run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'],
                           check=True, capture_output=True, text=True, timeout=5)
    if len(value.stdout) > 32768: raise ValueError('ROUTE_OUTPUT_REJECTED')
    rows = json.loads(value.stdout)
    if len(rows) != 1 or not isinstance(rows[0].get('dev'), str):
        raise ValueError('PHYSICAL_ROUTE_UNAVAILABLE')
    name = rows[0]['dev']
    if name in ('lo', 'wg0') or not 1 <= len(name) <= 15:
        raise ValueError('PHYSICAL_ROUTE_UNAVAILABLE')
    return name


def observe(seconds=DEFAULT_SECONDS):
    if type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError('BOUNDED_CAPTURE_REQUIRED')
    started = int(time.time())
    result = {'schema': 1, 'status': 'OBSERVATION_UNAVAILABLE', 'started_at': started,
              'duration_seconds': seconds, 'authentication_proof': False,
              'counts': empty(), 'windows': []}
    try:
        interface = physical_interface()
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            attach(sock)
            sock.bind((interface, 0))
            sock.settimeout(0.25)
            stop = time.monotonic() + seconds
            window_start = time.monotonic()
            window = empty()
            print('NATIVE_UDP_PASSIVE_CAPTURE=READY; bounded headers only; no IP or payload log', flush=True)
            while time.monotonic() < stop:
                try:
                    header, address = sock.recvfrom(72)
                    item = classify(header, address[2] == 4)  # PACKET_OUTGOING
                    increment(result['counts'], item)
                    increment(window, item)
                except socket.timeout:
                    pass
                if time.monotonic() - window_start >= 10:
                    result['windows'].append({'at': int(time.time()), 'counts': window})
                    window, window_start = empty(), time.monotonic()
            if any(window.values()):
                result['windows'].append({'at': int(time.time()), 'counts': window})
            stats = sock.getsockopt(263, 6, 8)  # SOL_PACKET / PACKET_STATISTICS
            result['socket_packets'], result['socket_drops'] = struct.unpack('II', stats)
            result['status'] = 'OBSERVED'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    result['finished_at'] = int(time.time())
    return result
