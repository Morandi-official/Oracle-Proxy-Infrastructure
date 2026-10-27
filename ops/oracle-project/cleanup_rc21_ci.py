"""Release one precisely identified, completed rc21 hosted acceptance device."""
import datetime as dt
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc21_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='rc21-owned-ci-slot-release-20261027'
VERSION='0.3.0-rc21+fc988d72983906b74aeb629163a8110bc36ee8ab'
MACHINE='runnervma5ucf'
cleanup.REQUEST=REQUEST
cleanup.BEGIN=int(dt.datetime(2026,10,27,3,30,49,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,27,3,30,51,tzinfo=dt.timezone.utc).timestamp())
cleanup.VERSION=VERSION
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']==MACHINE and row['machine_name']==MACHINE and
          row['client_version']==VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
          peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1:raise ValueError('EXACT_OWNED_RC21_DEVICE_NOT_UNIQUE')
    return keys


def apply():
    # Narrow the shared helper's three-peer bound for resumed one-shot plans too.
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(cleanup.MARKER.read_text())
        if not isinstance(plan,dict) or not isinstance(plan.get('keys'),list) or len(plan['keys'])>1:
            raise ValueError('ONE_OWNED_RC21_DEVICE_PLAN_REQUIRED')
    cleanup.apply()


cleanup.candidates=candidates
