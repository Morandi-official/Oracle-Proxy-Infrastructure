"""Publish only bounded, fixed-name probe results for the console."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PORTS = (443, 8443, 51820)
CONCLUSIONS = {'success': 'success', 'failure': 'failure', 'error': 'neutral'}


def read_results(path):
    results = {}
    if path.is_file():
        for line in path.read_text(encoding='utf-8-sig', errors='replace').splitlines():
            match = re.fullmatch(r'PORT_MONITOR (443|8443|51820) (success|failure|error)', line.strip())
            if match:
                port, outcome = match.groups()
                results[int(port)] = CONCLUSIONS[outcome]
    return results


def gh(path, data=None, method=None):
    args = ['gh', 'api', path]
    if method:
        args += ['--method', method, '--input', '-']
    result = subprocess.run(args, input=json.dumps(data) if data else None,
                            check=True, text=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout)


def main(platform, filename):
    repo = os.environ['GITHUB_REPOSITORY']
    revision = os.environ['GITHUB_SHA']
    run = os.environ['GITHUB_RUN_ID']
    if (os.environ.get('GITHUB_REF') != 'refs/heads/main' or platform not in ('windows', 'android')
            or not re.fullmatch(r'[0-9a-f]{40}', revision) or not run.isdecimal()):
        raise ValueError('Invalid monitor publication context')
    results = read_results(Path(filename))
    collection = f'repos/{repo}/check-runs'
    for port in PORTS:
        name = f'port-monitor/{platform}/{port}'
        conclusion = results.get(port, 'neutral')
        payload = {'name': name, 'status': 'completed', 'conclusion': conclusion,
                   'details_url': f'https://github.com/{repo}/actions/runs/{run}',
                   'completed_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}
        checks = gh(f'repos/{repo}/commits/{revision}/check-runs?check_name={name}')
        current = next((check for check in checks['check_runs']
                        if check['name'] == name and check['app']['slug'] == 'github-actions'), None)
        if current:
            gh(f"{collection}/{current['id']}", payload, 'PATCH')
        else:
            gh(collection, {**payload, 'head_sha': revision}, 'POST')
        print(f'{name} {conclusion}')


if __name__ == '__main__':
    main(*sys.argv[1:])
