"""Actual kernel filter proof in an empty disposable network namespace."""
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

if os.geteuid()!=0 or os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:
    raise SystemExit('ISOLATED_ROOT_NAMESPACE_REQUIRED')
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','address','add','10.0.0.6/32','dev','lo'],check=True)
source=Path(__file__).resolve().parents[2]/'server/admin-oracle/control/udp_capture.py'
spec=importlib.util.spec_from_file_location('capture',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,0) as observer:
    module.attach(observer);observer.bind(('lo',0x0003));observer.settimeout(.1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
        sender.bind(('127.0.0.1',35000));server.bind(('10.0.0.6',443));server.settimeout(1)
        business=struct.pack('<II',4,123)+b'SYNTHETIC_BUSINESS_CONTENT_NEVER_CAPTURE'
        sender.sendto(business,server.getsockname());assert server.recvfrom(512)[0]==business
        try:observer.recvfrom(80)
        except socket.timeout:pass
        else:raise AssertionError('BUSINESS_PACKET_PASSED_CAPTURE_FILTER')
        initiation=struct.pack('<II',1,123)+b'E'*140
        sender.sendto(initiation,server.getsockname());_,peer=server.recvfrom(512)
        response=struct.pack('<III',2,456,123)+b'K'*80
        server.sendto(response,peer)
        seen=set();until=time.monotonic()+2
        while time.monotonic()<until:
            try:header,metadata=observer.recvfrom(80)
            except socket.timeout:continue
            offset=(header[0]&15)*4
            kind=struct.unpack_from('<I',header,offset+8)[0]
            assert len(header)==offset+(20 if kind==2 else 16)
            assert b'E'*4 not in header and b'K'*4 not in header
            row=module.parse(header,metadata[2]==4)
            if row:seen.add(row['kind'])
        assert seen=={'initiation','response'},seen
print('REAL_KERNEL_DIAGNOSTIC_HEADERS_ONLY_NO_KEYS_OR_BUSINESS_PAYLOAD=PASS')
