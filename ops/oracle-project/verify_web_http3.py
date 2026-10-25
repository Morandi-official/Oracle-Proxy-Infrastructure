"""Public HTTP/3 control on existing UDP443, without accounts or device enrollment."""
import asyncio
import sys
import urllib.error
import urllib.request
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from verify_quic import HOST, Http3Probe


class WebProbe(Http3Probe):
    async def blocked_health(self):
        # This route deliberately returns 404 at Caddy, before the private app.
        self.http.send_headers(0,[(b':method',b'GET'),(b':scheme',b'https'),
                                 (b':authority',HOST.encode()),(b':path',b'/api/health')],end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self.status.get(),3)==b'404'


def advertised():
    # Real public TLS response: the namespace header fixture intentionally uses
    # plain HTTP, where Caddy removes an upstream's Alt-Svc advertisement.
    try:
        with urllib.request.urlopen('https://'+HOST+'/api/health',timeout=8) as response:
            return False
    except urllib.error.HTTPError as error:
        with error:return error.code==404 and 'h3=":443"' in error.headers.get('Alt-Svc','')
    except (OSError,ValueError):return False


async def probe():
    config=QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=HOST)
    async def request():
        async with connect('152.67.156.100',443,configuration=config,create_protocol=WebProbe) as client:
            return await client.blocked_health()
    try:return await asyncio.wait_for(request(),8)
    except (OSError,ValueError,ConnectionError,asyncio.TimeoutError):return False


if __name__=='__main__':
    if sys.argv[1:] not in ([],['--require-reachable']):raise ValueError('INVALID_ARGUMENTS')
    advertisement=advertised()
    print('PUBLIC_WEB_HTTP3_ADVERTISEMENT='+('PASS' if advertisement else 'MISSING_OR_UNAVAILABLE'))
    passed=asyncio.run(probe())
    print('PUBLIC_WEB_HTTP3_443='+('PASS' if passed else 'BLOCKED_OR_UNAVAILABLE'))
    if '--require-reachable' in sys.argv[1:] and not (passed and advertisement):raise SystemExit(1)
