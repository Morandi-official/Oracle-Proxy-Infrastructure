"""Real kernel BPF test in a disposable network namespace; no external traffic."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import time

if os.geteuid()!=0 or os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:
    raise SystemExit('ISOLATED_ROOT_NETWORK_NAMESPACE_REQUIRED')
subprocess.run(['ip','link','set','lo','up'],check=True)
spec=importlib.util.spec_from_file_location('packets',Path(__file__).with_name('native_udp_packets.py'))
packets=importlib.util.module_from_spec(spec);spec.loader.exec_module(packets)
with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003)) as capture:
    packets.attach(capture);capture.bind(('lo',0));capture.settimeout(.1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as noise, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        sender.bind(('127.0.0.1',35000))
        noise.bind(('127.0.0.1',42424));sender.sendto(b'PRIVATE_SYNTHETIC_NOISE',noise.getsockname())
        try:capture.recvfrom(72)
        except socket.timeout:pass
        else:raise AssertionError('UNRELATED_PORT_WAS_NOT_FILTERED')
        counts=packets.empty()
        for port in packets.PORTS:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as peer:
                peer.bind(('127.0.0.1',port));peer.settimeout(1)
                sender.sendto(b'\x01\x00\x00\x00'+b'S'*144,peer.getsockname())
                _,address=peer.recvfrom(4096)
                peer.sendto(b'\x02\x00\x00\x00'+b'R'*88,address)
                if port==8443:
                    sender.sendto(b'\xc3HTTP3',peer.getsockname())
                    _,address=peer.recvfrom(4096);peer.sendto(b'\xc3HTTP3',address)
        until=time.monotonic()+2
        while time.monotonic()<until:
            try:header,address=capture.recvfrom(72)
            except socket.timeout:continue
            ihl=(header[0]&15)*4
            assert len(header)==ihl+12,'KERNEL_COPIED_BEYOND_FOUR_BYTE_MESSAGE_TYPE'
            assert b'S'*8 not in header and b'R'*8 not in header
            packets.increment(counts,packets.classify(header,address[2]==4))
        for port in ('51820','443','8443'):
            assert counts[port].get('in_initiation',0)>0,counts
            assert counts[port].get('out_response',0)>0,counts
        assert counts['8443'].get('in_other',0)>0 and counts['8443'].get('out_other',0)>0
print('REAL_KERNEL_BPF_ONLY_TARGET_UDP_HEADERS_NO_PAYLOAD_AND_CORRECT_DIRECTIONS=PASS')
