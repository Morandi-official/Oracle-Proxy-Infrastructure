"""External QUIC TLS reachability only: no bearer, device registration or root key."""
import asyncio
import json
import sys
import urllib.request

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

HOST = 'vpn-admin.morandi.dpdns.org'


class Http3Probe(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.http=H3Connection(self._quic);self.status=asyncio.Queue()
    def quic_event_received(self,event):
        for item in self.http.handle_event(event):
            if isinstance(item,HeadersReceived):self.status.put_nowait(dict(item.headers).get(b':status'))
    async def health(self):
        self.http.send_headers(0,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',HOST.encode()),(b':path',b'/health')],end_stream=True);self.transmit()
        return await asyncio.wait_for(self.status.get(),3)==b'200'


async def probe(info, address='152.67.156.100'):
    if address not in ('152.67.156.100','141.147.78.44'):raise ValueError('FIXED_INGRESS_REQUIRED')
    config = QuicConfiguration(is_client=True, alpn_protocols=['oracle-wireguard-quic-v1'],
                               server_name=HOST, max_datagram_frame_size=1200)
    config.load_verify_locations(cadata=info['certificate'].encode('ascii'))
    async def handshake():
        async with connect(address,8443,configuration=config): return True
    try:
        await asyncio.wait_for(handshake(),8)
        print('PUBLIC_QUIC_TLS=PASS')
        if not info.get('http3'):
            print('PUBLIC_HTTP3=NOT_ADVERTISED_BY_CURRENT_DEPLOYMENT');return True
        config.alpn_protocols=['h3']
        async with connect(address,8443,configuration=config,create_protocol=Http3Probe) as client:
            if not await client.health(): raise ConnectionError()
        print('PUBLIC_HTTP3_HEALTH=PASS')
        return True
    except (OSError,ConnectionError,asyncio.TimeoutError):
        print('PUBLIC_QUIC_TLS=BLOCKED_OR_UNAVAILABLE')
        return False


def main():
    if sys.argv[1:] not in ([],['--require-reachable']): raise ValueError('INVALID_ARGUMENTS')
    with urllib.request.urlopen('https://'+HOST+'/api/client/quic-certificate',timeout=10) as response:
        data=response.read(8193)
        if len(data)>8192: raise ValueError('QUIC_METADATA_REJECTED')
        info=json.loads(data).get('quic')
    if not isinstance(info,dict) or info.get('port')!=8443 or not isinstance(info.get('certificate'),str):
        raise ValueError('QUIC_PUBLIC_CERTIFICATE_MISSING')
    if 'PRIVATE KEY' in info['certificate']: raise ValueError('QUIC_METADATA_REJECTED')
    passed=asyncio.run(probe(info))
    # Preparation releases advertise disabled until the external gate passes.
    # Once advertised, a failed public handshake is a deployment failure.
    if (info.get('enabled') is True or '--require-reachable' in sys.argv[1:]) and not passed: raise SystemExit(1)


if __name__ == '__main__': main()
