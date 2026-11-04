import socket
from datetime import timedelta
import subprocess
from pathlib import Path
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from .models import Audit, Snapshot
from . import host_health


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
    last=Snapshot.objects.order_by('-observed_at').first()
    health=host_health.sample((last.payload.get('health') or {}) if last else {})
    value['health']=health
    # Handshake metadata only, through the existing read-only socket role.
    try:
        from . import control,flclash
        flclash.observe_usage(control.call('state','system:health',{}))
    except (OSError,TimeoutError,ValueError):pass
    with transaction.atomic():
        before={a['code'] for a in (last.payload.get('health') or {}).get('alerts',[])} if last else set()
        after={a['code'] for a in health['alerts']}
        for code in sorted(after-before):Audit.objects.create(actor='collector:local-readonly',action='server.health.warning',resource=code)
        for code in sorted(before-after):Audit.objects.create(actor='collector:local-readonly',action='server.health.resolved',resource=code)
        Snapshot.objects.filter(observed_at__lt=now-timedelta(hours=6)).delete()
        Snapshot.objects.create(observed_at=now, payload=value)
        if last is None:Audit.objects.create(actor='collector:local-readonly', action='snapshot.received')
    return value
