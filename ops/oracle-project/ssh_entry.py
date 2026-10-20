"""Unprivileged SSH forced command. Does not interpret shell text or read secrets."""
import os
import re
import subprocess
import sys

OPERATIONS = frozenset(('preflight', 'install-runtime', 'configure', 'deploy', 'enable-https',
                        'status', 'logs', 'start', 'stop', 'restart', 'rollback'))


def parse_command(value):
    match = re.fullmatch(r'([a-z-]+) ([0-9a-f]{40})', value)
    if not match or match[1] not in OPERATIONS:
        raise ValueError('SSH_COMMAND_REJECTED')
    return [match[1], match[2]]


def main():
    try:
        arguments = parse_command(os.environ.get('SSH_ORIGINAL_COMMAND', ''))
    except ValueError:
        print('SSH_COMMAND_REJECTED', file=sys.stderr)
        return 2
    return subprocess.call(['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I',
                            '/usr/local/libexec/oracle-project/gate.py', *arguments])


if __name__ == '__main__':
    raise SystemExit(main())
