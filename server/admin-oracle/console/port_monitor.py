"""Read fixed, public GitHub status contexts written by the native probe workflow."""
from datetime import datetime
import json
from threading import Lock
from time import monotonic, time
from urllib.request import urlopen

URL = 'https://api.github.com/repos/Morandi-official/Oracle-Proxy-Infrastructure/commits/main/check-runs?per_page=100'
PORTS = (443, 8443, 51820)
PLATFORMS = ('windows', 'android')
MAX_AGE = 45 * 60
_refresh_lock = Lock()
_checked = -90.0
_latest = None


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
        if not 0 <= now-checked <= MAX_AGE or (key in verified and verified[key]['verified_at'] >= checked):
            continue
        verified[key] = {'result': state, 'verified_at': checked}
    return {'available': True, 'rows': [
        {'port': port, **{platform: verified.get((platform, port)) for platform in PLATFORMS}}
        for port in PORTS]}


def snapshot():
    global _checked, _latest
    # One shared cache in the console's threaded web worker. Never hold the
    # lock while another browser waits for the external status refresh.
    if monotonic()-_checked >= 90 and _refresh_lock.acquire(blocking=False):
        try:
            _checked = monotonic()
            with urlopen(URL, timeout=2) as response:
                body = response.read(262145)
            if len(body) > 262144:
                raise ValueError('PORT_STATUS_RESPONSE_TOO_LARGE')
            payload = json.loads(body)
            if not isinstance(payload.get('check_runs'), list):
                raise ValueError('PORT_STATUS_INVALID')
            _latest = payload['check_runs']
        except (OSError, ValueError, TypeError, AttributeError):
            _latest = None
        finally:
            _refresh_lock.release()
    status = format_status(_latest or [], time())
    status['available'] = _latest is not None
    return status
