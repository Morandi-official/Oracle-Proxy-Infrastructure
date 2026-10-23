"""Fixed local RPC; web workers have neither sudo nor direct WireGuard/firewall access."""
import json
import socket
import struct

SOCKET = '/run/oracle-proxy-control/control.sock'


def call(operation, actor, data):
    body = json.dumps({'operation':operation,'actor':actor,'data':data},separators=(',',':')).encode()+b'\n'
    if len(body)>16384: raise ValueError('REQUEST_TOO_LARGE')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(12); connection.connect(SOCKET)
        _, uid, _ = struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid != 0: raise OSError('Untrusted control service')
        connection.sendall(body); response = bytearray()
        while b'\n' not in response and len(response)<=1024*1024:
            chunk = connection.recv(65536)
            if not chunk: break
            response.extend(chunk)
    if len(response)>1024*1024 or not response.endswith(b'\n'): raise OSError('Invalid control response')
    value = json.loads(response)
    if not value.get('ok'): raise ValueError(value.get('error','CONTROL_UNAVAILABLE'))
    return value['data']
