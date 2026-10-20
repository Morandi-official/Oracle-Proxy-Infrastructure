"""Choose an allowlisted GitOps action; never put credentials in request.json."""
import json
import os
import re
import subprocess
from pathlib import Path

OPERATIONS = frozenset(('preflight', 'install-runtime', 'configure', 'deploy', 'enable-https',
                        'status', 'logs', 'start', 'stop', 'restart', 'rollback'))
REQUEST = 'ops/oracle-project/request.json'


def parse_request(body):
    if len(body) > 1024: raise ValueError('REQUEST_TOO_LARGE')
    value = json.loads(body)
    if (not isinstance(value, dict) or set(value) != {'operation', 'request_id'} or
        not isinstance(value['operation'], str) or value['operation'] not in OPERATIONS or not isinstance(value['request_id'], str) or
        not re.fullmatch(r'[a-z0-9-]{1,64}', value['request_id'])):
        raise ValueError('REQUEST_REJECTED')
    return value['operation']


def choose():
    if os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch':
        operation = os.environ.get('REQUESTED_OPERATION', '')
        if operation not in OPERATIONS: raise ValueError('REQUEST_REJECTED')
        return operation
    before = os.environ.get('BEFORE_REVISION', '')
    if re.fullmatch(r'[a-f0-9]{40}', before) and before != '0' * 40:
        changed = subprocess.check_output(['git', 'diff', '--name-only', before, 'HEAD'], text=True).splitlines()
        if changed == [REQUEST]: return parse_request(Path(REQUEST).read_bytes())
    return 'deploy'


if __name__ == '__main__':
    operation = choose()
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('operation=' + operation + '\n')
