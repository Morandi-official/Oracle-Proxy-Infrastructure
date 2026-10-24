"""Bounded public DNS controls from Oracle itself; no capture or configuration edits."""
import secrets
import socket
import struct
import time


def query(name, padding):
    identity = secrets.token_bytes(2)
    result = bytearray(identity + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01')
    for part in name.split('.'):
        result += bytes([len(part)]) + part.encode('ascii')
    result += b'\x00\x00\x01\x00\x01'
    result += b'\x00\x00\x29\x10\x00\x00\x00\x00\x00' + struct.pack('!HHH', padding+4, 12, padding) + bytes(padding)
    return bytes(result)


def observe():
    rows = []
    # At most 12 public requests / 24 seconds. No customer names or secrets.
    for label, address in (('primary','9.9.9.9'), ('secondary','149.112.112.112')):
        for cycle in range(2):
            for kind, name, padding in (('small_positive','example.com',64), ('large_positive','example.com',1200), ('large_negative','opx-'+secrets.token_hex(16)+'.example.com',1120)):
                packet = query(name,padding)
                row = {'target':label,'cycle':cycle,'kind':kind,'ipv4_bytes':len(packet)+28,'response':False}
                started = time.monotonic()
                try:
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
                        connection.settimeout(2)
                        connection.connect((address,9953))
                        connection.send(packet)
                        reply = connection.recv(4096)
                        row['response'] = len(reply)>=12 and reply[:2]==packet[:2] and bool(reply[2]&128)
                        if row['response']: row['rcode'] = reply[3]&15
                except OSError:
                    pass
                row['elapsed_ms'] = int((time.monotonic()-started)*1000)
                rows.append(row)
    return rows
