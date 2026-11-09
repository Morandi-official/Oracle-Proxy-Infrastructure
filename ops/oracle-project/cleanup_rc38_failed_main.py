"""Retire only the logged, terminated rc38 main acceptance identity."""
import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('rc38_owned_cleanup',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='retire-only-rc38-failed-ci-20261109'
cleanup.OPERATION='preflight'
cleanup.MARKER=cleanup.STATE/'retire-only-rc38-failed-ci-20261109.json'
VERSION='0.3.0-rc38+6c6dbe70e1678d59fc7a74df172c2120b64cf9b2'
BEGIN=int(dt.datetime(2026,11,9,13,42,45,tzinfo=dt.timezone.utc).timestamp())
END=int(dt.datetime(2026,11,9,13,43,15,tzinfo=dt.timezone.utc).timestamp())

def fingerprint(key):return hashlib.sha256(key.encode()).hexdigest()[:12]

def candidates(rows,peers,now):
    matched=[r for r in rows if fingerprint(r['key'])=='3fb26101d5c7']
    if len(matched)>1:raise ValueError('EXACT_CI_NOT_UNIQUE')
    for row in matched:
        if not (row['name']==row['machine_name'] and re.fullmatch(cleanup.HOSTED,row['machine_name'],re.I) and row['client_version']==VERSION and BEGIN<=row['confirmed_at']<=END):raise ValueError('EXACT_LOGGED_CI_PROFILE_REQUIRED')
        if peers.get(row['key'],{}).get('handshake',0)>now-180:raise ValueError('COMPLETED_CI_NOT_IDLE')
    return [r['key'] for r in matched]

cleanup.candidates=candidates

def apply():cleanup.apply()
