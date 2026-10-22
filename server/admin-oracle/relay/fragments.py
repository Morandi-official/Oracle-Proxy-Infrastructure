"""Bounded datagram framing: preserve WireGuard MTU over QUIC's 1200-byte path."""
import struct
import time

CHUNK = 1000
MAX_PACKET = 4096


def fragment(packet, number):
    if not 1 <= len(packet) <= MAX_PACKET: raise ValueError('PACKET_SIZE')
    count = (len(packet) + CHUNK - 1) // CHUNK
    return [struct.pack('!IHBB', number, len(packet), index, count) + packet[index*CHUNK:(index+1)*CHUNK]
            for index in range(count)]


class Reassembly:
    def __init__(self): self.pending = {}

    def receive(self, data):
        now = time.monotonic()
        self.pending = {key:value for key,value in self.pending.items() if now-value[0] < 2}
        if not 9 <= len(data) <= CHUNK+8: return None
        number, total, index, count = struct.unpack('!IHBB', data[:8])
        if not 1 <= total <= MAX_PACKET or count != (total+CHUNK-1)//CHUNK or index >= count: return None
        if len(data)-8 != min(CHUNK, total-index*CHUNK): return None
        if number not in self.pending:
            if len(self.pending) >= 64: return None
            self.pending[number] = (now, total, [None]*count)
        _, size, pieces = self.pending[number]
        if size != total: self.pending.pop(number); return None
        pieces[index] = data[8:]
        if any(piece is None for piece in pieces): return None
        self.pending.pop(number)
        return b''.join(pieces)
