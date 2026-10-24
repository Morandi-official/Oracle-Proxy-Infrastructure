"""Real isolated kernel apply/idempotence/rollback; never touch the runner NIC."""
import os
from pathlib import Path
import subprocess
import tempfile

import network_queue as queue

if os.geteuid()!=0 or os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')!='1':
    raise SystemExit('DISPOSABLE_ROOT_NETWORK_NAMESPACE_REQUIRED')
# Must be launched with unshare -n; otherwise refuse before creating an interface.
names=subprocess.check_output(['ip','-j','link','show'],text=True)
import json
if {row['ifname'] for row in json.loads(names)}!={'lo'}:raise SystemExit('EMPTY_NETWORK_NAMESPACE_REQUIRED')
subprocess.run(['ip','link','add',queue.DEVICE,'type','dummy'],check=True)
subprocess.run(['ip','link','set',queue.DEVICE,'up'],check=True)
subprocess.run(['tc','qdisc','replace','dev',queue.DEVICE,'root','pfifo_fast'],check=True)
with tempfile.TemporaryDirectory() as root:
    queue.STATE=Path(root)/'baseline.json'
    queue.apply();queue.apply()
    assert queue.observe()['kind']=='fq_codel'
    queue.restore();queue.restore()
    assert queue.default_fifo(queue.observe())
print('REAL_ISOLATED_FQ_CODEL_APPLY_IDEMPOTENCE_ROLLBACK=PASS')
