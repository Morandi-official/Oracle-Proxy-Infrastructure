"""Reclaim only the terminated accepted rc19 main-run device; never a real PC."""
import datetime as dt
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc19_main',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='webrtc-owned-ci-slot-release-v6-20261026'
cleanup.BEGIN=int(dt.datetime(2026,10,26,4,16,40,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,26,4,17,15,tzinfo=dt.timezone.utc).timestamp())
cleanup.VERSION='0.3.0-rc19+c0908e3c5ac9c7874158f96acdcdf030946170c4'
cleanup.MARKER=cleanup.STATE/'webrtc-ci-cleanup-20261026-v6.json'
MACHINE='runnervma5ucf'


def candidates(rows,peers,now):
    selected=[row['key'] for row in rows if row['name']==MACHINE and row['machine_name']==MACHINE and
              row['client_version']==cleanup.VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
              peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(selected)>1:raise ValueError('EXACT_OWNED_CI_DEVICE_NOT_UNIQUE')
    return selected


cleanup.candidates=candidates
apply=cleanup.apply
