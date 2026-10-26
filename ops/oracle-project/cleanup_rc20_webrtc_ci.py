"""Release only the completed, precisely identified rc20 hosted acceptance peer."""
import datetime as dt
import importlib.util
import re
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_rc20_browser',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='webrtc-rc20-owned-slot-release-v4-20261026'
cleanup.BEGIN=int(dt.datetime(2026,10,26,11,28,30,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,26,11,28,45,tzinfo=dt.timezone.utc).timestamp())
cleanup.VERSION='0.3.0-rc20+30f70a05110e5752581eccd8dd2ce1c97dffd682'
cleanup.MARKER=cleanup.STATE/'webrtc-rc20-owned-slot-release-v4-20261026.json'
MACHINE='Cloud WebRTC acceptance'


def candidates(rows,peers,now):
    keys=[row['key'] for row in rows if row['name']=='Cloud WebRTC acceptance' and re.fullmatch(cleanup.HOSTED,row['machine_name'],re.I) and
          row['client_version']==cleanup.VERSION and cleanup.BEGIN<=row['confirmed_at']<=cleanup.END and
          peers.get(row['key'],{}).get('handshake',0)<=now-180]
    if len(keys)>1:raise ValueError('EXACT_OWNED_RC20_DEVICE_NOT_UNIQUE')
    return keys


cleanup.candidates=candidates
apply=cleanup.apply
