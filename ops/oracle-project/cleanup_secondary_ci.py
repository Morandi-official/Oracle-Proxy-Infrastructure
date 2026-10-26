"""Reclaim only the terminated hosted rc18 control confirmed around 12:42 UTC."""
import datetime as dt
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_ci_1242',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='webrtc-owned-ci-slot-release-v5-20261026'
cleanup.BEGIN=int(dt.datetime(2026,10,25,12,40,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,25,12,45,tzinfo=dt.timezone.utc).timestamp())
cleanup.MARKER=cleanup.STATE/'webrtc-ci-cleanup-20261026-v5.json'
apply=cleanup.apply
