"""Only a public fixed-host TLS trust certificate; never a private key."""
import stat
import json
from pathlib import Path

from django.http import JsonResponse
from django.views.decorators.http import require_GET

from relay.settings import PUBLIC_QUIC_ENABLED



TRANSPORT_STATE=Path('/etc/oracle-proxy-quic/transport.json')


def transport_address():
    # Root-owned public metadata. Missing/invalid/foreign state uses the original
    # entrance; ordinary GUI input can never supply an arbitrary destination.
    try:
        info=TRANSPORT_STATE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>2048:return '152.67.156.100'
        value=json.loads(TRANSPORT_STATE.read_text('ascii'))
        if value=={'schema':1,'owner':'oracle-proxy-secondary-endpoint','transport_address':'141.147.78.44'}:return '141.147.78.44'
    except (OSError,ValueError):pass
    return '152.67.156.100'


def quic_info():
    try:
        path = Path('/etc/oracle-proxy-quic/certificate.pem')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 4096 or info.st_mode & 0o022:
            return None
        body = path.read_text('ascii')
        if not body.startswith('-----BEGIN CERTIFICATE-----') or 'PRIVATE KEY' in body: return None
        return {'port':8443, 'certificate':body, 'enabled':PUBLIC_QUIC_ENABLED,'http3':True}
    except (OSError, ValueError): return None


@require_GET
def public_certificate(request):
    result = JsonResponse({'quic':quic_info()})
    result['Cache-Control'] = 'no-store'
    return result


IPV6_STATE = Path('/etc/oracle-proxy-quic/ipv6.json')


def ipv6_info():
    try:
        info = IPV6_STATE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 2048:
            return None
        value = json.loads(IPV6_STATE.read_text('ascii'))
        if value == {'schema': 1, 'owner': 'oracle-proxy-ipv6-tunnel', 'egress': '2603:c020:c015:8100::10', 'prefix': 'fd42:6f70:78:77::/64'}:
            return value
    except (OSError, ValueError):
        pass
    return None
