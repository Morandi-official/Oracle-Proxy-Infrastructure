"""External QUIC TLS reachability only: no bearer, device registration or root key."""
import asyncio
import json
import urllib.request

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

HOST = 'vpn-admin.morandi.dpdns.org'


async def probe(info):
    config = QuicConfiguration(is_client=True, alpn_protocols=['oracle-wireguard-quic-v1'],
                               server_name=HOST, max_datagram_frame_size=1200)
    config.load_verify_locations(cadata=info['certificate'].encode('ascii'))
    async def handshake():
        async with connect('152.67.156.100',8443,configuration=config): return True
    try:
        await asyncio.wait_for(handshake(),8)
        print('PUBLIC_QUIC_TLS=PASS')
        return True
    except (OSError,ConnectionError,asyncio.TimeoutError):
        print('PUBLIC_QUIC_TLS=BLOCKED_OR_UNAVAILABLE')
        return False


def main():
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
    if info.get('enabled') is True and not passed: raise SystemExit(1)


if __name__ == '__main__': main()
