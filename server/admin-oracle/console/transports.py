"""Only a public fixed-host TLS trust certificate; never a private key."""
import stat
from pathlib import Path

from django.http import JsonResponse
from django.views.decorators.http import require_GET

from relay.settings import PUBLIC_QUIC_ENABLED


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
