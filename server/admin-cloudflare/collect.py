"""Convert the existing forced-command diagnostics to a strictly typed signed report.

No shell execution or SSH credentials here. stdin must be agent-status output.
Secrets come only from CI environment variables, never command-line arguments.
"""
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def parse_diagnostics(raw):
    if len(raw) > 8192:
        raise ValueError('diagnostics too large')
    values = {}
    allowed = {
        'ORACLE_READONLY_AGENT': {'OK'},
        'WG0_SERVICE': {'ACTIVE', 'INACTIVE'},
        'WG0_INTERFACE': {'PRESENT', 'ABSENT'},
        'UDP51820': {'LISTENING', 'NOT_LISTENING'},
    }
    for line in raw.splitlines():
        key, sep, value = line.partition('=')
        if key == 'AGENT_DEPLOYED_SHA' and sep and re.fullmatch(r'[a-f0-9]{40}', value):
            continue
        if key not in allowed or not sep or value not in allowed[key] or key in values:
            raise ValueError('unexpected diagnostics')
        values[key] = value
    if set(values) != set(allowed):
        raise ValueError('incomplete diagnostics')
    return values


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a signed report to another location.


def main():
    try:
        endpoint = os.environ['ADMIN_INGEST_URL']
        url = urllib.parse.urlsplit(endpoint)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.path != '/api/ingest' or url.query or url.fragment or url.port not in (None, 443)):
            raise ValueError('invalid endpoint')
        key = os.environ['ADMIN_INGEST_HMAC_KEY']
        revision = os.environ['GITHUB_SHA']
        node = os.environ.get('ADMIN_NODE_ID', 'oracle-primary')
        if not re.fullmatch(r'[0-9a-f]{64}', key) or not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('invalid credentials or revision')
        if not re.fullmatch(r'[a-z0-9-]{1,64}', node):
            raise ValueError('invalid node')
        values = parse_diagnostics(sys.stdin.read(8193))
        observed = int(time.time())
        body = json.dumps({
            'schema': 1, 'id': uuid.uuid4().hex, 'node_id': node, 'observed_at': observed,
            'source_revision': revision, 'wg_service': values['WG0_SERVICE'],
            'wg_interface': values['WG0_INTERFACE'], 'udp_listener': values['UDP51820'],
        }, separators=(',', ':')).encode()
        signature = hmac.new(key.encode(), str(observed).encode() + b'\n' + body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(endpoint, data=body, method='POST', headers={
            'Content-Type': 'application/json', 'X-Oracle-Timestamp': str(observed),
            'X-Oracle-Signature': signature,
        })
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if response.status != 202:
                raise ValueError('report not accepted')
        print('ADMIN_REPORT=ACCEPTED')
        return 0
    except (KeyError, ValueError, OSError, urllib.error.URLError):
        print('ADMIN_REPORT=FAILED_CHECK_CONFIGURATION_OR_CONNECTIVITY', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
