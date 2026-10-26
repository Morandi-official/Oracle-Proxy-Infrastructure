"""Public original-SNI TLS/HTTP3 check; no credentials, peer allocation or DNS edits."""
import asyncio
import http.client
import json
import socket
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from verify_quic import HOST, Http3Probe


def tcp(address):
    context=ssl.create_default_context()
    with socket.create_connection((address,443),timeout=8) as raw:
        with context.wrap_socket(raw,server_hostname=HOST) as stream:
            stream.sendall(('GET /privacy-check/ HTTP/1.1\r\nHost: '+HOST+'\r\nConnection: close\r\n\r\n').encode('ascii'))
            reply=http.client.HTTPResponse(stream);reply.begin()
            return reply.status==200


async def h3(address):
    config=QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=HOST)
    async def request():
        async with connect(address,443,configuration=config,create_protocol=Http3Probe) as client:
            client.http.send_headers(0,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',HOST.encode()),(b':path',b'/privacy-check/')],end_stream=True)
            client.transmit()
            return await asyncio.wait_for(client.status.get(),4)==b'200'
    return await asyncio.wait_for(request(),12)


def main():
    passed=True
    for address in ('152.67.156.100','141.147.78.44'):
        row={'address':address,'tls_tcp':False,'tls_http3':False,'tls_bypass':False}
        for name,probe in (('tls_tcp',lambda:tcp(address)),('tls_http3',lambda:asyncio.run(h3(address)))):
            try:row[name]=probe()
            except Exception as error:row[name+'_error_category']=type(error).__name__
        print('SECONDARY_PUBLIC_CONTROL='+json.dumps(row,sort_keys=True),flush=True)
        passed=passed and row['tls_tcp'] and row['tls_http3']
    if not passed:raise SystemExit(1)


if __name__=='__main__':main()
