"""Release one completed, pinned rc19 hosted WebRTC acceptance device only."""
import datetime as dt
import importlib.util
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('owned_rc19_webrtc',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='ipv6-owned-ci-slot-release-20261026'
cleanup.BEGIN=int(dt.datetime(2026,10,26,5,20,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,26,5,31,tzinfo=dt.timezone.utc).timestamp())
cleanup.VERSION='0.3.0-rc19+c0908e3c5ac9c7874158f96acdcdf030946170c4'
cleanup.MARKER=cleanup.STATE/'ipv6-owned-ci-slot-release-20261026.json'


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']=='Cloud WebRTC acceptance' and
          re.fullmatch(cleanup.HOSTED,row['machine_name'],re.I) and row['client_version']==cleanup.VERSION and
          cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1: raise ValueError('OWNED_WEBRTC_DEVICE_NOT_UNIQUE')
    return keys


cleanup.candidates=candidates
apply=cleanup.apply
