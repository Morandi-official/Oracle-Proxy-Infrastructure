"""Apply or roll back the exact password-enrollment web patch only."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request

APPLY = 'windows-enrollment-console-apply'
ROLLBACK = 'windows-enrollment-console-rollback'
REVIEW = 'native-enrollment-console-source-review'
CLIENT_API = Path('console/client_api.py')
BEFORE = 'd9e71822a6d8a3ef6d62f3f10f636f28a7406cd648cdb015b9f2751e70393820'
AFTER = '55060b107b05eceae5833a3dde35be4572944212eb0f8293a5bb1b8ae7995099'
RECEIPT = 'enrollment-console.json'


def enabled(operation, request):
    return operation == request.get('operation') == 'deploy' and request.get('request_id') in (APPLY, ROLLBACK)


def owned(path, kind):
    info = path.lstat()
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('CONSOLE_DEPLOYMENT_PATH_NOT_SEALED')
    return path


def digest(path):
    return hashlib.sha256(owned(path, stat.S_ISREG).read_bytes()).hexdigest()


def release_path(releases, revision):
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('CONSOLE_RELEASE_REVISION_REJECTED')
    return releases / revision


def active_release(host, releases):
    link = host.ROOT / 'current'
    info = link.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise ValueError('CONSOLE_CURRENT_LINK_REQUIRED')
    current = link.resolve(strict=True)
    if current.parent != releases or current != release_path(releases, current.name):
        raise ValueError('CONSOLE_CURRENT_RELEASE_REJECTED')
    return owned(current, stat.S_ISDIR)


def verify_unit(host):
    name = host.UNIT_NAMES[0]
    unit = owned(host.UNIT_DIR / name, stat.S_ISREG)
    if unit.read_bytes() != (host.SOURCE / 'deploy' / name).read_bytes():
        raise ValueError('CONSOLE_DEPLOYMENT_UNIT_CHANGED')
    result = host.command(['systemctl', 'show', '--property=FragmentPath,DropInPaths', name],
                          capture_output=True, text=True, timeout=8)
    if set(result.stdout.splitlines()) != {f'FragmentPath={unit}', 'DropInPaths='}:
        raise ValueError('CONSOLE_DEPLOYMENT_UNIT_OVERRIDE_PRESENT')


def release_digest(release):
    owned(release / CLIENT_API.parent, stat.S_ISDIR)
    return digest(release / CLIENT_API)


def shared_directory(previous, name):
    entry = previous / name
    if not entry.is_symlink():
        return owned(entry, stat.S_ISDIR)
    if entry.lstat().st_uid != 0:
        raise ValueError('CONSOLE_DEPENDENCY_LINK_NOT_OWNED')
    resolved = entry.resolve(strict=True)
    releases = previous.parent
    if resolved.name != name:
        raise ValueError('CONSOLE_DEPENDENCY_PATH_REJECTED')
    parent = resolved.parent
    if parent != releases.parent / 'shared':
        if parent.parent != releases or parent != release_path(releases, parent.name):
            raise ValueError('CONSOLE_DEPENDENCY_PATH_REJECTED')
    owned(parent, stat.S_ISDIR)
    return owned(resolved, stat.S_ISDIR)


def copy_active(source, destination, previous, reviewed):
    # Preserve the live release, including files outside the checked-out branch.
    # Runtime dependencies are reused below. No data or settings are read from
    # the mutable application state directory.
    owned(source, stat.S_ISDIR)
    for item in source.iterdir():
        if source == previous and item.name in ('.venv', 'staticfiles', 'revision.env'):
            continue
        path = destination / item.name
        if item.is_dir() and not item.is_symlink():
            path.mkdir()
            copy_active(item, path, previous, reviewed)
        else:
            original = owned(item, stat.S_ISREG)
            data = reviewed if item == previous / CLIENT_API else original
            shutil.copyfile(data, path)
        # Preserve permission bits from the original sealed release; the
        # trusted checkout and project gate create files under umask 077.
        shutil.copymode(item, path)
    shutil.copymode(source, destination)


def marker(release, predecessor):
    receipt = json.loads(owned(release / RECEIPT, stat.S_ISREG).read_text())
    if receipt != {'previous': predecessor.name, 'payload': AFTER} or release_digest(release) != AFTER:
        raise ValueError('CONSOLE_RELEASE_NOT_OWNED_BY_PATCH')


def stage(host, previous, target, reviewed):
    if target.exists() or target.is_symlink():
        # A previous invocation may have stopped after publishing the sealed
        # directory, but before validating or activating the web process.
        owned(target, stat.S_ISDIR)
        marker(target, previous)
    else:
        if (previous / RECEIPT).exists() or (previous / RECEIPT).is_symlink():
            raise ValueError('CONSOLE_PREDECESSOR_RECEIPT_CONFLICT')
        with tempfile.TemporaryDirectory(prefix='.console-', dir=target.parent) as temporary:
            candidate = Path(temporary) / target.name
            candidate.mkdir()
            copy_active(previous, candidate, previous, reviewed)
            for name in ('.venv', 'staticfiles'):
                (candidate / name).symlink_to(shared_directory(previous, name), target_is_directory=True)
            manifest = candidate / 'revision.env'
            manifest.write_text(f'ADMIN_SOURCE_REVISION={target.name}\n')
            manifest.chmod(0o644)
            (candidate / RECEIPT).write_text(json.dumps({'previous': previous.name, 'payload': AFTER}))
            (candidate / RECEIPT).chmod(0o600)
            candidate.rename(target)
    host.require_ingress_release(target)
    environment = host.read_environment()
    environment['ADMIN_SOURCE_REVISION'] = target.name
    host.as_user(host.APP_USER, [target / '.venv/bin/python', 'manage.py', 'check', '--deploy', '--fail-level', 'WARNING'],
                 cwd=target, env=environment)


def ready(host, release):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request('http://127.0.0.1:8787/api/health',
                                     headers={'Host': host.HOST, 'X-Forwarded-Proto': 'https'})
    for _ in range(15):
        try:
            main_pid = host.command(['systemctl', 'show', '--property=MainPID', '--value', host.UNIT_NAMES[0]],
                                    capture_output=True, text=True, timeout=4).stdout.strip()
            if not re.fullmatch(r'[1-9][0-9]{0,9}', main_pid) or Path(f'/proc/{main_pid}/cwd').resolve(strict=True) != release:
                raise ValueError('CONSOLE_RELEASE_PROCESS_NOT_CONFIRMED')
            with opener.open(request, timeout=2) as response:
                payload = json.loads(response.read(16385))
                if response.status == 200 and payload.get('ready') is True and payload.get('control', {}).get('ready') is True:
                    return True
        except (OSError, ValueError, AttributeError, subprocess.SubprocessError):
            pass
        time.sleep(1)
    return False


def activate(host, target, previous):
    restart = ['systemctl', '--job-mode=ignore-dependencies', 'restart', host.UNIT_NAMES[0]]
    host.switch(target)
    try:
        host.command(restart, timeout=45)
        if not ready(host, target):
            raise ValueError('CONSOLE_ACTIVATION_UNHEALTHY')
    except (OSError, ValueError, subprocess.SubprocessError):
        # Restore the active link before asking systemd to recover the process.
        host.switch(previous)
        host.command(restart, timeout=45)
        if not ready(host, previous):
            raise ValueError('CONSOLE_PREVIOUS_RELEASE_RECOVERY_UNVERIFIED')
        raise


def inspect(host):
    owned(host.ROOT, stat.S_ISDIR)
    releases = owned(host.ROOT / 'releases', stat.S_ISDIR)
    current = active_release(host, releases)
    verify_unit(host)
    observed = release_digest(current)
    print(f'PROJECT_ENROLLMENT_CONSOLE_RELEASE={current.name} SOURCE_SHA256={observed}', flush=True)
    if observed not in (BEFORE, AFTER) or digest(host.SOURCE / CLIENT_API) != AFTER:
        raise ValueError('CONSOLE_ENROLLMENT_PATCH_NOT_EXACT')
    for name in ('.venv', 'staticfiles'):
        shared_directory(current, name)
    return current, observed


def change(host, request, revision):
    if not enabled('deploy', request):
        raise ValueError('CONSOLE_DEPLOYMENT_REQUEST_REJECTED')
    current, observed = inspect(host)
    target = release_path(current.parent, revision)
    rollback = request['request_id'] == ROLLBACK
    if observed == BEFORE:
        if not ready(host, current):
            raise ValueError('CONSOLE_PREDECESSOR_UNHEALTHY')
        if rollback:
            print('PROJECT_ENROLLMENT_CONSOLE=ALREADY_ROLLED_BACK')
            return
        stage(host, current, target, host.SOURCE / CLIENT_API)
        activate(host, target, current)
    else:
        receipt = json.loads(owned(current / RECEIPT, stat.S_ISREG).read_text())
        previous = owned(release_path(current.parent, receipt['previous']), stat.S_ISDIR)
        marker(current, previous)
        if release_digest(previous) != BEFORE:
            raise ValueError('CONSOLE_PREVIOUS_RELEASE_NOT_EXACT')
        if rollback:
            activate(host, previous, current)
            print('PROJECT_ENROLLMENT_CONSOLE=ROLLED_BACK')
            return
        if not ready(host, current):
            activate(host, current, previous)
    print('PROJECT_ENROLLMENT_CONSOLE=ACTIVE')


def dispatch(host, operation, request, revision):
    review = request.get('request_id') == REVIEW and request.get('operation') == 'preflight'
    apply = enabled('deploy', request)
    if not ((operation == 'preflight' and (review or apply)) or (operation == 'deploy' and apply)):
        return False
    try:
        if operation == 'preflight':
            inspect(host)
        else:
            change(host, request, revision)
    except ValueError as exc:
        # Only known-format reason codes can enter CI logs.
        reason = str(exc)
        if re.fullmatch(r'CONSOLE_[A-Z_]+', reason):
            print(f'PROJECT_ENROLLMENT_CONSOLE_FAILED={reason}', flush=True)
        raise
    return True
