"""One-shot cleanup of this turn's own terminated hosted acceptance devices only."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import subprocess
import tempfile
import time

REQUEST='webrtc-owned-ci-slot-release-v2-20261024'
OPERATION='enable-https'
HOSTED=r'(?:fv-az[0-9]+-[0-9]+|runnervm[a-z0-9]{1,32})'
BEGIN=int(dt.datetime(2026,10,24,15,44,tzinfo=dt.timezone.utc).timestamp())
END=int(dt.datetime(2026,10,24,16,44,30,tzinfo=dt.timezone.utc).timestamp())
VERSION='0.3.0-rc18+41169fd6fca86815d67d7566bdc45c4cfcbacaa1'
STATE=Path('/var/lib/oracle-proxy-control')
MARKER=STATE/'webrtc-ci-cleanup-20261024-v2.json'


def candidates(rows,peers,now):
    selected=[]
    for row in rows:
        if (row['name']!='Cloud WebRTC acceptance' or row['client_version']!=VERSION or
            not re.fullmatch(HOSTED,row['machine_name'],re.I) or
            not BEGIN<=row['confirmed_at']<=END or peers.get(row['key'],{}).get('handshake',0)>now-180):continue
        selected.append(row)
    return [r['key'] for r in sorted(selected,key=lambda r:r['confirmed_at'])[:3]]


def save(value):
    fd,name=tempfile.mkstemp(prefix='.ci-cleanup-',dir=STATE)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,MARKER)
    finally:
        if os.path.exists(name):os.unlink(name)


def apply():
    if os.geteuid()!=0:raise ValueError('ROOT_ONLY')
    request=json.loads(Path(__file__).with_name('request.json').read_text())
    if request.get('request_id')!=REQUEST or request.get('operation')!=OPERATION:raise ValueError('EXPLICIT_CI_CLEANUP_REQUEST_REQUIRED')
    if MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if MARKER.exists():
        if MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(MARKER.read_text())
    else:
        source=Path(__file__).resolve().parents[2]/'server/admin-oracle/control/agent.py'
        spec=importlib.util.spec_from_file_location('ci_readonly_observation',source)
        agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
        observed=agent.Driver().observe() # Read only; never instantiates Engine or resets leases.
        with sqlite3.connect('file:'+str(STATE/'ledger.sqlite3')+'?mode=ro',uri=True) as db:
            db.row_factory=sqlite3.Row
            rows=db.execute('SELECT d.key,d.name,e.machine_name,e.client_version,e.confirmed_at FROM devices d JOIN device_enrollments e ON e.key=d.key AND e.user_id=d.user_id WHERE d.key NOT IN (SELECT key FROM revoked_devices)').fetchall()
        plan={'keys':candidates(rows,observed['peers'],int(time.time())),'done':False}
        print('CI_OWNED_WEBRTC_EXACT_HOSTED_MATCH_COUNT='+str(len(plan['keys'])))
        save(plan) # Persist the exact plan so retries can never select another batch.
    if set(plan)!={'keys','done'} or type(plan['done']) is not bool or not isinstance(plan['keys'],list) or len(plan['keys'])>3 or any(not re.fullmatch(r'[A-Za-z0-9+/]{43}=',k) for k in plan['keys']):raise ValueError('INVALID_CLEANUP_PLAN')
    if plan['done']:print('CI_OWNED_WEBRTC_DEVICE_CLEANUP=ALREADY_DONE');return
    account=pwd.getpwnam('oracle-proxy-admin')
    code="import sys;sys.path.insert(0,'/opt/oracle-proxy-admin/current');from console.control import call;call('peer.revoke','github:204281968',{'public_key':sys.stdin.read().strip()});print('REVOKED')"
    for key in plan['keys']:
        result=subprocess.run(['/opt/oracle-proxy-admin/current/.venv/bin/python','-I','-c',code],input=key,text=True,capture_output=True,timeout=20,user=account.pw_uid,group=account.pw_gid,extra_groups=[])
        if result.returncode!=0 or result.stdout.strip()!='REVOKED':raise ValueError('OWNED_CI_DEVICE_REVOKE_FAILED')
    plan['done']=True;save(plan)
    print('CI_OWNED_WEBRTC_DEVICE_REVOKED_COUNT='+str(len(plan['keys'])))


def observe_only():
    """Bounded aggregate metadata; no keys, usernames or machine names leave host."""
    if os.geteuid()!=0:raise ValueError('ROOT_ONLY')
    with sqlite3.connect('file:'+str(STATE/'ledger.sqlite3')+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        rows=db.execute('SELECT d.key,d.name,e.machine_name,e.client_version,e.confirmed_at FROM devices d JOIN device_enrollments e ON e.key=d.key AND e.user_id=d.user_id WHERE d.key NOT IN (SELECT key FROM revoked_devices)').fetchall()
    named=[r for r in rows if r['name']=='Cloud WebRTC acceptance']
    window=[r for r in named if BEGIN<=r['confirmed_at']<=END]
    versions=sorted({r['client_version'] for r in window if re.fullmatch(r'(?:0\.3\.0-rc18|1\.0\.0)(?:\+[a-f0-9]{7,40})?',r['client_version'])})
    print('CI_OWNED_WEBRTC_DEVICE_SCOPE='+json.dumps({'named':len(named),'window':len(window),'azure_pattern':sum(bool(re.fullmatch(r'fv-az[0-9]+-[0-9]+',r['machine_name'],re.I)) for r in window),'exact_version':sum(r['client_version']==VERSION for r in window),'versions':versions},sort_keys=True))
