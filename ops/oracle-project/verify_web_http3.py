"""Public HTTP/3 control on existing UDP443, without accounts or device enrollment."""
import asyncio
import sys
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


async def probe():
    config=QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=HOST)
    async def request():
        async with connect('152.67.156.100',443,configuration=config,create_protocol=WebProbe) as client:
            return await client.blocked_health()
    try:return await asyncio.wait_for(request(),8)
    except (OSError,ValueError,ConnectionError,asyncio.TimeoutError):return False


if __name__=='__main__':
    if sys.argv[1:] not in ([],['--require-reachable']):raise ValueError('INVALID_ARGUMENTS')
    passed=asyncio.run(probe())
    print('PUBLIC_WEB_HTTP3_443='+('PASS' if passed else 'BLOCKED_OR_UNAVAILABLE'))
    if '--require-reachable' in sys.argv[1:] and not passed:raise SystemExit(1)
