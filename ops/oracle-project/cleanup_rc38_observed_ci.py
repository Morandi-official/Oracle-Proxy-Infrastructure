"""Retire only the two recorded failed exit-observation CI identities."""
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import re
spec=importlib.util.spec_from_file_location('observed_ci_cleanup',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='retire-rc38-observed-ci-two-20261109';cleanup.OPERATION='preflight'
cleanup.MARKER=cleanup.STATE/'retire-rc38-observed-ci-two-20261109.json'
def stamp(hour,minute,second):return int(dt.datetime(2026,11,9,hour,minute,second,tzinfo=dt.timezone.utc).timestamp())
PROFILES={
 '1120413c4b22':('0.3.0-rc38+53e66a373633b6e2b3d911e303811e9849bcd5fd',stamp(14,9,35),stamp(14,10,8)),
 '8b0a2b8f013d':('0.3.0-rc38+534b0c889febad93f1b661276698f821bfe56b09',stamp(14,27,50),stamp(14,28,23)),
}
def fingerprint(key):return hashlib.sha256(key.encode()).hexdigest()[:12]
def candidates(rows,peers,now):
    keys=[];seen=set()
    for row in rows:
        value=fingerprint(row['key'])
        if value not in PROFILES:continue
        version,begin,end=PROFILES[value]
        if value in seen:raise ValueError('EXACT_OBSERVED_CI_NOT_UNIQUE')
        seen.add(value)
        if not (row['name']==row['machine_name'] and re.fullmatch(cleanup.HOSTED,row['machine_name'],re.I) and row['client_version']==version and begin<=row['confirmed_at']<=end):raise ValueError('EXACT_LOGGED_OBSERVATION_PROFILE_REQUIRED')
        if peers.get(row['key'],{}).get('handshake',0)>now-180:raise ValueError('COMPLETED_OBSERVATION_NOT_IDLE')
        keys.append(row['key'])
    return keys
cleanup.candidates=candidates
def apply():
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        value=json.loads(cleanup.MARKER.read_text())
        if not isinstance(value,dict) or not isinstance(value.get('keys'),list) or len(value['keys'])>2:raise ValueError('BOUNDED_OBSERVATION_PLAN_REQUIRED')
    cleanup.apply()
