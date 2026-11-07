"""Retire only exact, completed hosted rc32 acceptance identities; no user devices."""
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc32_completed_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='retire-only-rc32-completed-ci-20261107'
# Inclusive UTC windows derived from the runner-name and registration PASS logs.
PROFILES=[{'machine': 'runnervmquqza', 'version': '0.3.0-rc32+b77dd2e450ac38176feae2c959c07a2023e8fffb', 'begin': 1794040037, 'end': 1794040158}, {'machine': 'runnervmquqza', 'version': '0.3.0-rc32+b77dd2e450ac38176feae2c959c07a2023e8fffb', 'begin': 1794040948, 'end': 1794041069}, {'machine': 'runnervmquqza', 'version': '0.3.0-rc32+8fc0c7d748e5df610133880363484c8a4f9a0825', 'begin': 1794042555, 'end': 1794042676}]
if not 1<=len(PROFILES)<=3:raise ValueError('BOUNDED_COMPLETED_RC32_PROFILES_REQUIRED')
cleanup.REQUEST=REQUEST
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')


def candidates(rows,peers,now):
    keys=[]
    for profile in PROFILES:
        matched=[row['key'] for row in rows if row['name']==profile['machine'] and
                 row['machine_name']==profile['machine'] and row['client_version']==profile['version'] and
                 profile['begin']<=row['confirmed_at']<=profile['end']]
        if len(matched)>1:raise ValueError('EXACT_COMPLETED_RC32_CI_DEVICE_NOT_UNIQUE')
        if any(peers.get(key,{}).get('handshake',0)>now-180 for key in matched):
            raise ValueError('COMPLETED_RC32_CI_DEVICE_NOT_IDLE')
        keys.extend(matched)
    if len(keys)!=len(set(keys)):raise ValueError('OVERLAPPING_RC32_CI_PROFILES')
    return keys


def apply():
    if cleanup.MARKER.is_symlink():raise ValueError('UNTRUSTED_CLEANUP_MARKER')
    if cleanup.MARKER.exists():
        if cleanup.MARKER.stat().st_size>4096:raise ValueError('INVALID_CLEANUP_MARKER')
        plan=json.loads(cleanup.MARKER.read_text())
        if not isinstance(plan,dict) or not isinstance(plan.get('keys'),list) or len(plan['keys'])>len(PROFILES):
            raise ValueError('BOUNDED_COMPLETED_RC32_CI_DEVICE_PLAN_REQUIRED')
    cleanup.apply()


cleanup.candidates=candidates
