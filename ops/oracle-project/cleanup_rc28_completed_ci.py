"""Release one exact, completed rc28 hosted device; preserve real computers."""
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc28_completed_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='deliver-windows-rc28-and-retire-ci-20261104'
VERSION='0.3.0-rc28+e91bf7f59a185c9125d07083d7f4665587bd6220'
MACHINE='runnervmnjgfq'
cleanup.REQUEST=REQUEST
cleanup.BEGIN=1793769161 # 2026-11-04T05:12:41Z: exact completed main registration window.
cleanup.END=1793769181 # 2026-11-04T05:13:01Z.
cleanup.VERSION=VERSION
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']==MACHINE and row['machine_name']==MACHINE and
          row['client_version']==VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
          peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1:raise ValueError('EXACT_COMPLETED_RC28_CI_DEVICE_NOT_UNIQUE')
    return keys


def apply():
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(cleanup.MARKER.read_text())
        if not isinstance(plan,dict) or not isinstance(plan.get('keys'),list) or len(plan['keys'])>1:
            raise ValueError('ONE_COMPLETED_RC28_CI_DEVICE_PLAN_REQUIRED')
    cleanup.apply()


cleanup.candidates=candidates
