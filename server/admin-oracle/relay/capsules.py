"""Bounded RFC9298 DATAGRAM capsules (context0) for large WG UDP payloads."""
def varint(value):
    if value<64:return bytes([value])
    if value<16384:return (value|0x4000).to_bytes(2,'big')
    raise ValueError('CAPSULE_SIZE_REJECTED')
def encode(packet):return b'\0'+varint(len(packet)+1)+b'\0'+packet
class Capsules:
    def __init__(self):self.pending=bytearray()
    def receive(self,data):
        if len(self.pending)+len(data)>16384:raise ValueError('CAPSULE_BUFFER_REJECTED')
        self.pending.extend(data);packets=[]
        def read(at):
            if at>=len(self.pending):return None
            size=1<<(self.pending[at]>>6)
            if at+size>len(self.pending):return None
            return int.from_bytes(self.pending[at:at+size],'big')&((1<<(size*8-2))-1),at+size
        while self.pending:
            kind=read(0)
            if kind is None:break
            length=read(kind[1])
            if length is None:break
            total,at=length
            if kind[0]!=0 or not 1<=total<=4097:raise ValueError('CAPSULE_REJECTED')
            if len(self.pending)<at+total:break
            if self.pending[at]!=0:raise ValueError('CONTEXT_REJECTED')
            packets.append(bytes(self.pending[at+1:at+total]));del self.pending[:at+total]
        return packets
