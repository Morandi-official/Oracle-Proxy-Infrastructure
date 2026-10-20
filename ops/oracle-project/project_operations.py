"""Project operations executed as root only after the SSH bridge verifies current main."""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / 'server/admin-oracle'
CADDY_MAIN = Path('/etc/caddy/Caddyfile')
CADDY_DIRECTORY = Path('/etc/caddy/oracle-proxy-admin')
WEB_BACKUPS = Path('/var/backups/oracle-project-ops')
spec = importlib.util.spec_from_file_location('oracle_admin_host', SERVER / 'deploy/host.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def runtime_python():
    for name in ('python3.13', 'python3.12', 'python3.11', 'python3'):
        binary = shutil.which(name)
        if binary and subprocess.run([binary, '-c', 'import sys;sys.exit(sys.version_info<(3,11))'],
                                     check=False, stdout=subprocess.DEVNULL).returncode == 0:
            return binary
    raise ValueError('PYTHON_311_OR_NEWER_REQUIRED')


def preflight():
    try:
        value = host.preflight()
    except OSError:
        value = {'required_network_inspection_tools': 'missing'}
    value['os_release'] = Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else 'unknown'
    value['application_configured'] = False
    try:
        host.read_environment(); value['application_configured'] = True
    except (OSError, ValueError):
        pass
    print(json.dumps(value, indent=2))


def install_runtime():
    try:
        python = runtime_python()
        if shutil.which('caddy') and subprocess.run([python, '-c', 'import venv,ensurepip'],
                                                  check=False, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.DEVNULL).returncode == 0:
            print('PROJECT_RUNTIME=ALREADY_READY'); return
    except ValueError:
        pass
    # These are fixed distro packages, not caller-provided package names or scripts.
    if not shutil.which('apt-get'):
        raise ValueError('RUNTIME_AUTOMATION_CURRENTLY_REQUIRES_APT_DISTRO')
    run(['apt-get', 'update'], env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    run(['apt-get', 'install', '-y', '--no-install-recommends', 'python3-venv', 'caddy'],
        env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    try:
        runtime_python()
    except ValueError:
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'python3.11', 'python3.11-venv'],
            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    runtime_python()
    print('PROJECT_RUNTIME=READY')


def parse_configuration(body):
    if len(body) > 4096:
        raise ValueError('CONFIGURATION_REJECTED')
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        raise ValueError('CONFIGURATION_REJECTED') from None
    if not isinstance(value, dict) or set(value) != {'client_id', 'client_secret'}:
        raise ValueError('CONFIGURATION_REJECTED')
    if (not isinstance(value['client_id'], str) or not re.fullmatch(r'[A-Za-z0-9]{8,100}', value['client_id']) or
        not isinstance(value['client_secret'], str) or not re.fullmatch(r'[A-Za-z0-9_=-]{16,256}', value['client_secret'])):
        raise ValueError('CONFIGURATION_REJECTED')
    return value


def configure(body):
    value = parse_configuration(body)
    try:
        host.prepare_configuration()
    except ValueError:
        # First creation intentionally writes a protected placeholder config.
        # Validate ownership independently before changing only OAuth fields.
        pass
    info = host.regular(host.CONFIG)
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('UNTRUSTED_HOST_CONFIGURATION')
    old = host.CONFIG.read_bytes()
    text = old.decode()
    for name, key in (('ADMIN_GITHUB_CLIENT_ID', 'client_id'), ('ADMIN_GITHUB_CLIENT_SECRET', 'client_secret')):
        text, count = re.subn(r'^' + name + r'=.*$', name + '=' + value[key], text, flags=re.MULTILINE)
        if count != 1: raise ValueError('HOST_CONFIGURATION_FIELD_MISSING')
    atomic(host.CONFIG, text.encode(), 0o600)
    try: host.read_environment()
    except Exception:
        atomic(host.CONFIG, old, 0o600)
        raise
    print('PROJECT_OAUTH_CONFIGURATION=UPDATED; existing session and MFA keys retained')


def atomic(path, body, mode):
    if path.is_symlink(): raise ValueError('SYMLINK_CONFIGURATION_REJECTED')
    descriptor, temporary = tempfile.mkstemp(prefix='.oracle-project-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream: stream.write(body)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def deploy(revision):
    current = host.ROOT / 'current'
    if current.is_symlink() and current.resolve().name == revision:
        run(['systemctl', 'restart', host.UNIT_NAMES[0]])
        if not host.healthy(): raise ValueError('APPLICATION_UNHEALTHY')
        print('PROJECT_DEPLOYMENT=ALREADY_CURRENT_HEALTHY'); return
    python = runtime_python()
    run([python, '-I', str(SERVER / 'deploy/host.py'), 'install', '--revision', revision])


def enable_https():
    main = CADDY_MAIN
    directory = CADDY_DIRECTORY
    snippet = directory / 'admin.caddy'
    if main.is_symlink() or directory.is_symlink() or snippet.is_symlink():
        raise ValueError('SYMLINK_WEB_CONFIGURATION_REJECTED')
    existed = main.exists()
    info = main.stat() if existed else None
    original = main.read_bytes() if existed else b''
    main_mode = (info.st_mode & 0o777) if info else 0o644
    previous_snippet = snippet.read_bytes() if snippet.exists() else None
    marker = b'import /etc/caddy/oracle-proxy-admin/*.caddy'
    if host.HOST.encode() in original:
        raise ValueError('HOST_ALREADY_DEFINED_IN_EXISTING_WEB_CONFIGURATION')
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    directory.chmod(0o755)
    backup_dir = WEB_BACKUPS
    if backup_dir.is_symlink(): raise ValueError('SYMLINK_BACKUP_DIRECTORY_REJECTED')
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_dir.chmod(0o700)
    # Preserve the exact prior files, including a missing snippet, for host recovery.
    backup = backup_dir / ('caddy-' + str(os.stat(main).st_mtime_ns if main.exists() else 0))
    if not backup.exists(): atomic(backup, original, 0o600)
    if previous_snippet is not None:
        atomic(backup_dir / 'previous-admin.caddy', previous_snippet, 0o600)
    updated = original if marker in original.splitlines() else original + b'\n' + marker + b'\n'
    atomic(snippet, (SERVER / 'deploy/Caddyfile').read_bytes(), 0o644)
    candidate = main.parent / '.oracle-project-candidate'
    atomic(candidate, updated, 0o644)
    try:
        run(['caddy', 'validate', '--config', str(candidate), '--adapter', 'caddyfile'])
        atomic(main, updated, main_mode)
        if info is not None: os.chown(main, info.st_uid, info.st_gid)
        run(['systemctl', 'reload', 'caddy'])
    except Exception:
        if existed:
            atomic(main, original, main_mode)
            os.chown(main, info.st_uid, info.st_gid)
        else: main.unlink(missing_ok=True)
        if previous_snippet is None: snippet.unlink(missing_ok=True)
        else: atomic(snippet, previous_snippet, 0o644)
        subprocess.run(['systemctl', 'reload', 'caddy'], check=False, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        raise
    finally:
        candidate.unlink(missing_ok=True)
    print('PROJECT_HTTPS_CONFIGURATION=ENABLED; existing Caddy hosts preserved')


def status():
    for unit in host.UNIT_NAMES:
        result = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState,SubState,User'],
                                capture_output=True, text=True, check=False)
        print(unit + '\n' + result.stdout.strip())


def logs():
    result = subprocess.run(['journalctl', '--no-pager', '-n', '80', '-u', host.UNIT_NAMES[0],
                             '-u', host.UNIT_NAMES[1]], capture_output=True, text=True, check=False)
    text = result.stdout
    try:
        for key, value in host.read_environment().items():
            if 'SECRET' in key or 'KEY' in key:
                text = text.replace(value, '[REDACTED]')
    except (OSError, ValueError):
        # No raw diagnostic log is exported when redaction keys are unavailable.
        print('PROJECT_LOGS=UNAVAILABLE_UNTIL_CONFIGURATION_READY'); return
    print(text)


def main(arguments):
    if os.geteuid() != 0 or len(arguments) != 2 or not re.fullmatch(r'[a-f0-9]{40}', arguments[1]):
        raise ValueError('ROOT_PROJECT_OPERATION_REQUIRED')
    operation, revision = arguments
    if operation == 'preflight': preflight()
    elif operation == 'install-runtime': install_runtime()
    elif operation == 'configure': configure(sys.stdin.buffer.read(4097))
    elif operation == 'deploy': deploy(revision)
    elif operation == 'enable-https': enable_https()
    elif operation == 'status': status()
    elif operation == 'logs': logs()
    elif operation in ('start', 'stop', 'restart'):
        run(['systemctl', operation, host.UNIT_NAMES[0]])
    elif operation == 'rollback': host.rollback()
    else: raise ValueError('OPERATION_REJECTED')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('PROJECT_OPERATION_FAILED_CHECK_PREFLIGHT_OR_SERVICE_STATUS', file=sys.stderr)
        raise SystemExit(2) from None
