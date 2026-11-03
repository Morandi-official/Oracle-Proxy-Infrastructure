"""Read-only fixed public ingress metadata and owned unit readiness."""
import json
import stat
import subprocess
from pathlib import Path

STATE = Path('/etc/oracle-proxy-quic/transport.json')
APP_USER = 'oracle-proxy-admin'
UNIT = 'oracle-proxy-secondary-endpoint.service'
PRIMARY = '152.67.156.100'
SECONDARY = '141.147.78.44'
EXPECTED = {'schema': 1, 'owner': 'oracle-proxy-secondary-endpoint',
            'transport_address': SECONDARY}


def observe():
    result = {'metadata_status': 'UNAVAILABLE', 'backend_readable': None,
              'expected_advertised_address': PRIMARY, 'secondary_unit': {},
              'scope': 'HOST_STATE_ONLY_NOT_CLIENT_PATH_PROOF'}
    try:
        info = STATE.lstat()
        parent = STATE.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or not 0 < info.st_size <= 2048 or
                not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
                parent.st_mode & 0o022):
            result['metadata_status'] = 'UNTRUSTED_OR_INVALID'
        elif json.loads(STATE.read_text('ascii')) != EXPECTED:
            result['metadata_status'] = 'UNEXPECTED_CONTENT'
        else:
            result['metadata_status'] = 'VALID_SECONDARY'
            check = subprocess.run(['runuser', '-u', APP_USER, '--', 'test',
                                    '-r', str(STATE)], check=False,
                                   capture_output=True, timeout=5)
            result['backend_readable'] = check.returncode == 0
            if result['backend_readable']:
                result['expected_advertised_address'] = SECONDARY
    except FileNotFoundError:
        result['metadata_status'] = 'MISSING'
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    try:
        text = subprocess.run(
            ['systemctl', 'show', UNIT,
             '--property=ActiveState,SubState,UnitFileState,NRestarts,ExecMainStatus'],
            check=True, capture_output=True, text=True, timeout=5).stdout
        if len(text) <= 4096:
            allowed = {'ActiveState', 'SubState', 'UnitFileState', 'NRestarts',
                       'ExecMainStatus'}
            result['secondary_unit'] = {
                key: value for row in text.splitlines() if '=' in row
                for key, value in [row.split('=', 1)]
                if key in allowed and len(value) <= 32 and
                all(c.isascii() and (c.isalnum() or c == '-') for c in value)
            }
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return result
