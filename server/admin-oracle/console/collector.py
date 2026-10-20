import socket
import subprocess
from pathlib import Path
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from .models import Audit, Snapshot


def collect():
    # Fixed read-only OS queries; no request-controlled arguments or shell.
    result = subprocess.run(['/usr/bin/systemctl', 'is-active', 'wg-quick@wg0'],
                            capture_output=True, text=True, timeout=5, check=False)
    if (result.returncode, result.stdout.strip()) not in ((0, 'active'), (3, 'inactive'), (3, 'failed')):
        raise RuntimeError('Service observation unavailable')
    interfaces = {name for _, name in socket.if_nameindex()}
    listening = False
    for name in ('udp', 'udp6'):
        path = Path('/proc/net') / name
        if not path.exists() and name == 'udp6':
            continue
        for line in path.read_text().splitlines()[1:]:
            columns = line.split()
            if len(columns) >= 2 and int(columns[1].rsplit(':', 1)[1], 16) == 51820:
                listening = True
    now = timezone.now()
    value = {'schema': 1, 'node_id': settings.NODE_ID, 'observed_at': int(now.timestamp()),
             'source_revision': settings.SOURCE_REVISION,
             'wg_service': 'ACTIVE' if result.returncode == 0 else 'INACTIVE',
             'wg_interface': 'PRESENT' if 'wg0' in interfaces else 'ABSENT',
             'udp_listener': 'LISTENING' if listening else 'NOT_LISTENING'}
    with transaction.atomic():
        Snapshot.objects.create(observed_at=now, payload=value)
        Audit.objects.create(actor='collector:local-readonly', action='snapshot.received')
    return value
