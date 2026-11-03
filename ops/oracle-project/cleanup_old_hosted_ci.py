"""Release at most three old hosted CI peers; preserve real PCs and audit history."""
import datetime as dt
import importlib.util
import re
from pathlib import Path
spec=importlib.util.spec_from_file_location('bounded_old_ci',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
REQUEST='old-hosted-ci-three-slots-20261103'
cleanup.REQUEST=REQUEST
cleanup.MARKER=cleanup.STATE/(REQUEST+'.json')
BEGIN=int(dt.datetime(2026,10,24,tzinfo=dt.timezone.utc).timestamp())
END=int(dt.datetime(2026,11,2,tzinfo=dt.timezone.utc).timestamp())
VERSIONS={
'0.3.0-rc18+41169fd6fca86815d67d7566bdc45c4cfcbacaa1',
'0.3.0-rc20+30f70a05110e5752581eccd8dd2ce1c97dffd682',
'0.3.0-rc22+3bc9e40b9a14db438c3d6e35df9b47f64cb88b13',
'0.3.0-rc23+d27da2b8ed07b527fb734c17810c33648e4b2963'}
def candidates(rows,peers,now):
    selected=[]
    for row in rows:
        machine=row['machine_name']
        if (not re.fullmatch(cleanup.HOSTED,machine,re.I) or
            row['name'] not in (machine,'Cloud WebRTC acceptance') or
            row['client_version'] not in VERSIONS or
            not BEGIN<=row['confirmed_at']<END or
            row['confirmed_at']>now-86400 or
            peers.get(row['key'],{}).get('handshake',0)>now-86400):continue
        selected.append(row)
    return [r['key'] for r in sorted(selected,key=lambda r:(r['confirmed_at'],r['key']))[:3]]
cleanup.candidates=candidates
def apply():cleanup.apply()
