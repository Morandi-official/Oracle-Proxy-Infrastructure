"""Release one exact, completed rc26 hosted device; preserve real computers."""
import datetime as dt
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc26_completed_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='rc26-completed-owned-ci-slot-release-20261104'
VERSION='0.3.0-rc26+41dfa4eefaeaa295aa1b9cfb480ffdf771876701'
MACHINE='runnervmnjgfq'
cleanup.REQUEST=REQUEST
cleanup.BEGIN=int(dt.datetime(2026,11,3,13,36,45,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,11,3,13,37,5,tzinfo=dt.timezone.utc).timestamp())
cleanup.VERSION=VERSION
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']==MACHINE and row['machine_name']==MACHINE and
          row['client_version']==VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
          peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1:raise ValueError('EXACT_COMPLETED_RC26_CI_DEVICE_NOT_UNIQUE')
    return keys


def apply():
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(cleanup.MARKER.read_text())
        if not isinstance(plan,dict) or not isinstance(plan.get('keys'),list) or len(plan['keys'])>1:
            raise ValueError('ONE_COMPLETED_RC26_CI_DEVICE_PLAN_REQUIRED')
    cleanup.apply()


cleanup.candidates=candidates
