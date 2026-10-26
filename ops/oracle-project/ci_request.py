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
        # An explicitly updated request may accompany a diagnostics implementation fix.
        if REQUEST in changed: return parse_request(Path(REQUEST).read_bytes())
    return 'deploy'


if __name__ == '__main__':
    operation = choose()
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('operation=' + operation + '\n')
        request=json.loads(Path(REQUEST).read_text())
        secondary=operation=='enable-https' and request.get('request_id') in ('secondary-endpoint-apply-20261026','secondary-vpn-promote-20261026')
        stream.write('secondary_endpoint='+str(secondary).lower()+'\n')
        stream.write('secondary_vpn='+str(secondary and request.get('request_id')=='secondary-vpn-promote-20261026').lower()+'\n')
        stream.write('boot_observer='+str(operation=='enable-https' and request.get('request_id')=='windows-rc20-boot-observer-20261026').lower()+'\n')
