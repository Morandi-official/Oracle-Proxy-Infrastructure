"""Release one exact, completed rc31 hosted device; preserve real computers."""
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc31_completed_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='deliver-windows-rc31-and-retire-ci-20261106'
VERSION='0.3.0-rc31+2e1e584fd2d71badd9d6a3a6e76cd5b7527c68e1'
MACHINE='runnervmquqza'
cleanup.REQUEST=REQUEST
cleanup.BEGIN=1793956535 # 2026-11-06T09:15:35Z: exact completed main confirmation window.
cleanup.END=1793956555 # 2026-11-06T09:15:55Z.
cleanup.VERSION=VERSION
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']==MACHINE and row['machine_name']==MACHINE and
          row['client_version']==VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
          peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1:raise ValueError('EXACT_COMPLETED_RC31_CI_DEVICE_NOT_UNIQUE')
    return keys


def apply():
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(cleanup.MARKER.read_text())
        if not isinstance(plan,dict) or not isinstance(plan.get('keys'),list) or len(plan['keys'])>1:
            raise ValueError('ONE_COMPLETED_RC31_CI_DEVICE_PLAN_REQUIRED')
    cleanup.apply()


cleanup.candidates=candidates
