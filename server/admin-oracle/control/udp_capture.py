"""On-demand WireGuard HEADER observations, never keys or business payloads.

Sender/receiver indices are public, unauthenticated protocol identifiers. Counts
must be displayed separately from authenticated kernel handshake evidence.
"""
from collections import deque
import ctypes
import json
import socket
import struct
import subprocess
import threading
import time

PORTS=(443,8443,51820)
ADDRESSES={'152.67.156.100':socket.inet_aton('10.0.0.6'),
           '141.147.78.44':socket.inet_aton('10.0.0.10')}
# SOCK_DGRAM AF_PACKET begins at IP. BPF rejects data packets and truncates an initiation/cookie
# packet after type+index; a response after type+sender+receiver. No part of
# the handshake's ephemeral key, cookie, authenticator or data is copied.
FILTER=(
    (0x30,0,0,0),(0x54,0,0,0xf0),(0x15,0,13,0x40),
    (0x30,0,0,9),(0x15,0,11,17),
    (0x28,0,0,6),(0x45,9,0,0x1fff),(0xb1,0,0,0),
    (0x48,0,0,2),(0x15,7,0,51820),(0x15,6,0,443),(0x15,5,0,8443),
    (0x48,0,0,0),(0x15,3,0,51820),(0x15,2,0,443),(0x15,1,0,8443),
    (0x06,0,0,0),
    (0x50,0,0,8),(0x15,0,3,2),
    (0x87,0,0,0),(0x04,0,0,20),(0x16,0,0,0),
    (0x15,1,0,1),(0x15,0,3,3),
    (0x87,0,0,0),(0x04,0,0,16),(0x16,0,0,0),(0x06,0,0,0),
)


class Instruction(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('instructions',ctypes.POINTER(Instruction))]


def attach(sock):
    values=(Instruction*len(FILTER))(*(Instruction(*row) for row in FILTER))
    sock.setsockopt(socket.SOL_SOCKET,26,bytes(Program(len(FILTER),values)))


def parse(header,outgoing):
    if len(header)<20 or header[0]>>4!=4 or header[9]!=17:return None
    ihl=(header[0]&15)*4
    if ihl<20 or len(header)<ihl+16 or struct.unpack_from('!H',header,6)[0]&0x1fff:return None
    source,destination,length=struct.unpack_from('!HHH',header,ihl)
    port=source if outgoing else destination
    address=bytes(header[12:16] if outgoing else header[16:20])
    if port not in PORTS or address not in ADDRESSES.values():return None
    kind,index=struct.unpack_from('<II',header,ihl+8)
    if kind==1 and not outgoing and length==156:fields={'kind':'initiation','client_index':index}
    elif kind==2 and outgoing and length==100 and len(header)>=ihl+20:
        fields={'kind':'response','server_index':index,'client_index':struct.unpack_from('<I',header,ihl+16)[0]}
    elif kind==3 and outgoing and length==72:fields={'kind':'cookie','client_index':index}
    else:return None
    return {**fields,'address':next(k for k,v in ADDRESSES.items() if v==address),
            'port':port,'outgoing':outgoing,'udp_bytes':length}


def summarize(records,address,port,indices,since):
    if address not in ADDRESSES or port not in PORTS or not isinstance(indices,list) or len(indices)>16 or any(type(i)!=int or not 0<=i<2**32 for i in indices):
        raise ValueError('INVALID_DIAGNOSTIC_CORRELATION')
    matched=[r for r in records if r['at']>=since and r['address']==address and r['port']==port]
    own=set(indices)
    counters={'rx_initiations':0,'tx_responses':0,'tx_cookies':0}
    for row in matched:
        if row['kind']=='initiation' and row['client_index'] in own:counters['rx_initiations']+=1
        elif row['kind']=='response' and row['client_index'] in own:counters['tx_responses']+=1
        elif row['kind']=='cookie' and row['client_index'] in own:counters['tx_cookies']+=1
    return {**counters,'correlation':'public_wireguard_indices','authentication_proof':False}


class Capture:
    def __init__(self,seconds=180):
        if type(seconds)!=int or not 1<=seconds<=180:raise ValueError('BOUNDED_CAPTURE_REQUIRED')
        self.seconds=seconds;self.records=deque(maxlen=2048);self.evicted=0
        self.lock=threading.Lock();self.stop=threading.Event();self.ready=threading.Event()
        self.status='starting';self.socket_drops=None;self.started=None
        self.thread=threading.Thread(target=self._run,name='udp-diagnostic',daemon=True)
        self.thread.start()

    def _run(self):
        try:
            observed=subprocess.run(['ip','-j','-4','route','get','1.1.1.1'],text=True,capture_output=True,check=True,timeout=5)
            rows=json.loads(observed.stdout)
            if len(rows)!=1 or rows[0].get('dev')!='enp0s6':raise ValueError('PHYSICAL_INTERFACE_NOT_VERIFIED')
            # Protocol zero keeps reception disabled until the header-only
            # filter is attached. Otherwise packets could queue unfiltered
            # between socket creation and SO_ATTACH_FILTER.
            with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,0) as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,262144)
                attach(sock);sock.bind(('enp0s6',0x0003));sock.settimeout(.1)
                self.started=time.monotonic();self.status='observing';self.ready.set();end=time.monotonic()+self.seconds
                while not self.stop.is_set() and time.monotonic()<end:
                    try:
                        header,metadata=sock.recvfrom(80)
                        row=parse(header,metadata[2]==4)
                        if row:
                            row['at']=time.monotonic()
                            with self.lock:
                                if len(self.records)==self.records.maxlen:self.evicted+=1
                                self.records.append(row)
                    except socket.timeout:pass
                _,self.socket_drops=struct.unpack('II',sock.getsockopt(263,6,8))
                self.status='complete'
        except Exception:
            self.status='unavailable'
        finally:self.ready.set()

    def report(self,address,port,indices,since):
        with self.lock:
            counts=summarize(list(self.records),address,port,indices,since)
            return {**counts,'capture_status':self.status,'ring_evictions':self.evicted,
                    'socket_drops':self.socket_drops,'complete_observation':self.status in ('observing','complete') and self.evicted==0 and self.socket_drops==0 and self.started is not None and self.started<=since}

    def close(self):
        # Route discovery can still be inside its five-second subprocess
        # deadline when cancellation arrives. A successful finish must mean
        # the observer thread actually ended, rather than merely signalled.
        self.stop.set();self.thread.join(timeout=6)
        if self.thread.is_alive():raise TimeoutError('DIAGNOSTIC_CAPTURE_STOP_NOT_VERIFIED')
