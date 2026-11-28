"""Read fixed, public GitHub status contexts written by the native probe workflow."""
from datetime import datetime
import json
import re
from threading import Lock
from time import monotonic, time
from urllib.request import urlopen

REPOSITORY = 'https://api.github.com/repos/Morandi-official/Oracle-Proxy-Infrastructure'
RUNS = '/actions/workflows/native-port-monitor.yml/runs?branch=main&status=completed&per_page=1'
PORTS = (443, 8443, 51820)
PLATFORMS = ('windows', 'android')
MAX_AGE = 45 * 60
_refresh_lock = Lock()
RETENTION = 7 * 24 * 60 * 60
_checked = -150.0
_latest = []
_available = False


def format_status(statuses, now):
    verified = {}
    for report in statuses:
        try:
            prefix, platform, port_text = report['name'].split('/')
            port = int(port_text)
            state = {'success': 'success', 'failure': 'failure', 'neutral': 'error'}.get(report['conclusion'])
            if (prefix != 'port-monitor' or platform not in PLATFORMS or port not in PORTS
                    or report['app']['slug'] != 'github-actions'
                    or state not in ('success', 'failure', 'error')):
                continue
            checked = int(datetime.fromisoformat(report['completed_at'].replace('Z', '+00:00')).timestamp())
        except (TypeError, KeyError, AttributeError, ValueError, OverflowError):
            continue
        key = (platform, port)
        age = now - checked
        if not 0 <= age <= RETENTION or (key in verified and verified[key]['verified_at'] >= checked):
            continue
        verified[key] = {'result': state, 'verified_at': checked, 'stale': age > MAX_AGE}
    return {'available': True, 'rows': [
        {'port': port, **{platform: verified.get((platform, port)) for platform in PLATFORMS}}
        for port in PORTS]}


def github_json(path):
    with urlopen(REPOSITORY + path, timeout=2) as response:
        body = response.read(262145)
    if len(body) > 262144:
        raise ValueError('PORT_STATUS_RESPONSE_TOO_LARGE')
    return json.loads(body)


def latest_reports():
    runs = github_json(RUNS)['workflow_runs']
    if not isinstance(runs, list):
        raise ValueError('PORT_MONITOR_RUNS_INVALID')
    if not runs:
        return []
    revision = runs[0]['head_sha']
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('PORT_MONITOR_REVISION_INVALID')
    checks = github_json(f'/commits/{revision}/check-runs?per_page=100')['check_runs']
    if not isinstance(checks, list):
        raise ValueError('PORT_STATUS_INVALID')
    return checks


def snapshot():
    global _checked, _latest, _available
    # One shared cache in the console's threaded web worker. Never hold the
    # lock while another browser waits for the external status refresh.
    if monotonic()-_checked >= 150 and _refresh_lock.acquire(blocking=False):
        try:
            _checked = monotonic()
            _latest = latest_reports()
            _available = True
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            _available = False
        finally:
            _refresh_lock.release()
    status = format_status(_latest, time())
    status['available'] = _available
    return status
