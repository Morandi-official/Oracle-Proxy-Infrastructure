"""Owned, reversible FQ-CoDel policy for this project's physical egress only.

No shaper, MTU, firewall, route, sysctl or WireGuard changes. Refuse unfamiliar
queue hierarchies. Called only by an explicitly named GitOps request or its unit.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

DEVICE = 'enp0s6'
STATE = Path('/var/lib/oracle-project-ops/network-queue.json')
SCRIPT = Path('/usr/local/libexec/oracle-project/network_queue.py')
UNIT = Path('/etc/systemd/system/oracle-proxy-network-queue.service')
PRIOMAP = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10)


def observe():
    result = run(['tc', '-j', '-s', 'qdisc', 'show', 'dev', DEVICE])
    if len(result.stdout) > 16384: raise ValueError('QUEUE_OBSERVATION_LIMIT')
    rows = json.loads(result.stdout)
    if len(rows) != 1 or rows[0].get('dev', DEVICE) != DEVICE or rows[0].get('root') is not True:
        raise ValueError('SINGLE_PHYSICAL_ROOT_QUEUE_REQUIRED')
    return rows[0]


def default_fifo(row):
    options = row.get('options', {})
    return (row.get('kind') == 'pfifo_fast' and
            options.get('bands', 3) == 3 and options.get('priomap', PRIOMAP) == PRIOMAP and
            set(options) <= {'bands', 'priomap', 'multiqueue'})


def owned_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('ROOT_OWNED_REGULAR_FILE_REQUIRED')


def write(path, data, mode=0o600):
    if path.exists() or path.is_symlink(): owned_file(path)
    temporary = path.with_name(path.name + '.candidate')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as output: output.write(data); output.flush(); os.fsync(output.fileno())
        temporary.replace(path)
    finally: temporary.unlink(missing_ok=True)


def baseline():
    owned_file(STATE)
    value = json.loads(STATE.read_text())
    if value != {'schema': 1, 'device': DEVICE, 'previous': 'pfifo_fast'}:
        raise ValueError('EXACT_QUEUE_BASELINE_REQUIRED')


def restore():
    baseline()
    row = observe()
    if default_fifo(row): return
    if row.get('kind') != 'fq_codel': raise ValueError('EXTERNAL_QUEUE_CHANGE_REFUSE_ROLLBACK')
    run(['tc', 'qdisc', 'replace', 'dev', DEVICE, 'root', 'pfifo_fast'])
    if not default_fifo(observe()): raise ValueError('QUEUE_ROLLBACK_NOT_VERIFIED')


def apply():
    row = observe()
    if STATE.exists(): baseline()
    elif default_fifo(row):
        # Retain the original baseline across idempotent applications/reboots.
        write(STATE, json.dumps({'schema': 1, 'device': DEVICE, 'previous': 'pfifo_fast'}).encode())
    else: raise ValueError('DEFAULT_FIFO_BASELINE_REQUIRED')
    if row.get('kind') not in ('pfifo_fast', 'fq_codel') or row.get('kind') == 'pfifo_fast' and not default_fifo(row):
        raise ValueError('EXTERNAL_QUEUE_CHANGE_REFUSE_APPLY')
    if row.get('kind') == 'fq_codel':
        print('PROJECT_NETWORK_QUEUE=FQ_CODEL_ALREADY_PRESENT; BASELINE_VERIFIED')
        return
    try:
        run(['tc', 'qdisc', 'replace', 'dev', DEVICE, 'root', 'fq_codel',
             'limit', '1024', 'flows', '1024', 'target', '5ms', 'interval', '100ms', 'ecn'])
        if observe().get('kind') != 'fq_codel': raise ValueError('QUEUE_APPLY_NOT_VERIFIED')
    except Exception:
        restore()
        raise
    print('PROJECT_NETWORK_QUEUE=FQ_CODEL; DEVICE=enp0s6; NO_RATE_LIMIT_ADDED')


def install():
    # Verify the interface and baseline before writing persistent files.
    row = observe()
    if STATE.exists(): baseline()
    elif not default_fifo(row): raise ValueError('DEFAULT_FIFO_BASELINE_REQUIRED')
    write(SCRIPT, Path(__file__).read_bytes())
    unit = '''[Unit]
Description=Oracle Proxy reversible physical egress queue policy
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I /usr/local/libexec/oracle-project/network_queue.py --apply
ExecStop=/usr/bin/python3 -I /usr/local/libexec/oracle-project/network_queue.py --rollback
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
'''
    write(UNIT, unit.encode(), 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'oracle-proxy-network-queue.service'])
    try:
        run(['systemctl', 'start', 'oracle-proxy-network-queue.service'])
        if observe().get('kind') != 'fq_codel': raise ValueError('PERSISTENT_QUEUE_NOT_VERIFIED')
    except Exception:
        run(['systemctl', 'disable', 'oracle-proxy-network-queue.service'])
        if STATE.exists(): restore()
        raise
    print('PROJECT_NETWORK_QUEUE_PERSISTENCE=ENABLED; ROLLBACK_REQUEST_SUPPORTED')


def uninstall():
    # ExecStop restores the original default FIFO, including across shutdown.
    run(['systemctl', 'disable', '--now', 'oracle-proxy-network-queue.service'])
    restore()
    print('PROJECT_NETWORK_QUEUE=RESTORED_DEFAULT_FIFO')


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 2: raise SystemExit('ROOT_QUEUE_OPERATION_REQUIRED')
    {'--apply': apply, '--rollback': restore}[sys.argv[1]]()
