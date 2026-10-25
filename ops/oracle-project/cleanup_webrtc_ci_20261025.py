"""Fixed one-shot scope: terminated hosted rc18 acceptance devices from Oct 25."""
import datetime as dt
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('owned_ci_oct25',Path(__file__).with_name('cleanup_webrtc_ci.py'))
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)
cleanup.REQUEST='webrtc-owned-ci-slot-release-v3-20261025'
cleanup.BEGIN=int(dt.datetime(2026,10,25,0,0,tzinfo=dt.timezone.utc).timestamp())
cleanup.END=int(dt.datetime(2026,10,25,9,26,tzinfo=dt.timezone.utc).timestamp())
cleanup.MARKER=cleanup.STATE/'webrtc-ci-cleanup-20261025-v3.json'
# Reuse exact hosted name/version/idle checks and the persisted <=3-key plan.
apply=cleanup.apply
