"""Reclaim only the terminated hosted rc18 control confirmed around 09:41 UTC."""
import datetime as dt
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_ci_0941',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='webrtc-owned-ci-slot-release-v4-20261025'
cleanup.BEGIN=int(dt.datetime(2026,10,25,9,40,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,25,9,42,tzinfo=dt.timezone.utc).timestamp())
cleanup.MARKER=cleanup.STATE/'webrtc-ci-cleanup-20261025-v4.json'
apply=cleanup.apply
