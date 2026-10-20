#!/usr/bin/env python3
"""Attended host bootstrap and version activation; NEVER exposed to HTTP.

The existing oracle-ci forced command cannot invoke this root-only tool.
No wg0, SSH daemon, routes, firewall, or existing web-server config is changed.
"""
import argparse
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path('/opt/oracle-proxy-admin')
STATE = Path('/var/lib/oracle-proxy-admin')
CONFIG = Path('/etc/oracle-proxy-admin/admin.env')
UNIT_DIR = Path('/etc/systemd/system')
APP_USER = 'oracle-proxy-admin'
BUILD_USER = 'oracle-proxy-admin-build'
SOURCE = Path(__file__).resolve().parents[1]
UNIT_NAMES = ('oracle-proxy-admin.service', 'oracle-proxy-admin-collect.service',
              'oracle-proxy-admin-collect.timer')
HOST = 'vpn-admin.morandi.dpdns.org'


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def preflight():
    tools = {name: shutil.which(name) is not None for name in ('python3', 'systemctl', 'caddy', 'runuser')}
    listeners = subprocess.run(['ss', '-H', '-ltn', '( sport = :80 or sport = :443 or sport = :8787 )'],
                               capture_output=True, text=True, check=False)
    return {'architecture': platform.machine(), 'python': platform.python_version(),
            'tools': tools, 'web_listener_present': bool(listeners.stdout.strip()),
            'service_registered': (UNIT_DIR / UNIT_NAMES[0]).exists(),
            'caddy_config_present': Path('/etc/caddy/Caddyfile').exists()}


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f'Refusing non-regular file: {path.name}')
    return info


def read_environment():
    info = regular(CONFIG)
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('admin.env must be root-owned with mode 0600')
    values = {}
    for line in CONFIG.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'ADMIN_[A-Z_]+', key) or not value or any(c.isspace() for c in value):
            raise ValueError('Invalid admin.env; use unquoted KEY=value with no whitespace')
        values[key] = value
    if any(values.get(k, '').startswith('REPLACE_') or not values.get(k) for k in
           ('ADMIN_GITHUB_CLIENT_ID', 'ADMIN_GITHUB_CLIENT_SECRET')):
        raise ValueError('Fill GitHub OAuth credentials in /etc/oracle-proxy-admin/admin.env first')
    return values


def create_user(name, home):
    try:
        pwd.getpwnam(name)
    except KeyError:
        command(['useradd', '--system', '--user-group', '--home-dir', str(home),
                 '--shell', '/usr/sbin/nologin', name])


def prepare_configuration():
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.parent.chmod(0o700)
    if not CONFIG.exists():
        # No real secret is printed. Generate once and preserve during all upgrades.
        import base64
        content = (
            f'ADMIN_SECRET_KEY={secrets.token_urlsafe(64)}\n'
            f'ADMIN_MFA_ENCRYPTION_KEY={base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}\n'
            'ADMIN_GITHUB_CLIENT_ID=REPLACE_WITH_CLIENT_ID\n'
            'ADMIN_GITHUB_CLIENT_SECRET=REPLACE_WITH_CLIENT_SECRET\n'
            f'ADMIN_HOST={HOST}\nADMIN_GITHUB_IDS=204281968\nADMIN_STATE_DIR={STATE}\n')
        fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        raise ValueError('Configuration created. Use sudoedit /etc/oracle-proxy-admin/admin.env, then retry')
    return read_environment()


def source_files(source):
    result = []
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        if any(part in ('.venv', '__pycache__', 'staticfiles', 'dist', '.git') for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError('Source symlinks are not accepted')
        if path.is_file() and (path.suffix in ('.py', '.html', '.css', '.js') or path.name == 'requirements.txt'):
            if relative.parts[0] == 'deploy' or path.name in ('tests.py', 'test_settings.py'):
                continue
            result.append((path, relative))
    if not any(str(relative) == 'manage.py' for _, relative in result):
        raise ValueError('Missing application source')
    # Do not permit URLs, editable installs, flags or source trees in dependency input.
    for line in (source / 'requirements.txt').read_text().splitlines():
        if line and not re.fullmatch(r'[A-Za-z0-9_.-]+==[A-Za-z0-9.+-]+', line):
            raise ValueError('Only exact package version pins are accepted')
    return result


def as_user(user, args, *, cwd, env=None):
    safe = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
            'HOME': '/nonexistent', 'PIP_NO_CACHE_DIR': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    if env:
        safe.update(env)
    runuser = shutil.which('runuser') or '/usr/sbin/runuser'
    return command([runuser, '-u', user, '--', *map(str, args)], cwd=cwd, env=safe)


def seal_tree(path):
    for directory, subdirs, filenames in os.walk(path, followlinks=False):
        for item in [Path(directory)] + [Path(directory) / name for name in subdirs + filenames]:
            info = item.lstat()
            os.chown(item, 0, 0, follow_symlinks=False)
            if not stat.S_ISLNK(info.st_mode):
                item.chmod(0o755 if item.is_dir() or info.st_mode & 0o111 else 0o644)


def switch(release):
    temporary = ROOT / '.next'
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(release)
    temporary.replace(ROOT / 'current')


def healthy():
    request = urllib.request.Request(f'http://127.0.0.1:8787/api/health', headers={
        'Host': HOST, 'X-Forwarded-Proto': 'https'})
    # Do not route the local probe through external HTTP proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(15):
        try:
            with opener.open(request, timeout=2) as response:
                if response.status == 200 and json.load(response) == {'ready': True}:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(1)
    return False


def install(revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('A full source commit SHA is required')
    if sys.version_info < (3, 11):
        raise ValueError('Python 3.11 or newer is required')
    manifest = SOURCE / 'SOURCE_REVISION'
    if manifest.exists():
        regular(manifest)
        if manifest.read_text().strip() != revision:
            raise ValueError('Revision does not match the reviewed build artifact')
    if not all(preflight()['tools'].values()):
        raise ValueError('Install Python with venv, systemd, runuser and Caddy before bootstrap')
    environment = prepare_configuration()
    files = source_files(SOURCE)
    if ROOT.is_symlink() or STATE.is_symlink():
        raise ValueError('Application root and state directory must not be symlinks')
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    (ROOT / 'releases').mkdir(exist_ok=True)
    (ROOT / 'releases').chmod(0o755)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    create_user(APP_USER, STATE)
    create_user(BUILD_USER, '/nonexistent')
    app = pwd.getpwnam(APP_USER)
    os.chown(STATE, app.pw_uid, app.pw_gid); STATE.chmod(0o700)
    release = ROOT / 'releases' / revision
    if release.exists():
        raise ValueError('Release already exists; use a new source revision or inspect previous attempt')
    release.mkdir(parents=True)
    release.chmod(0o755)
    for source, relative in files:
        destination = release / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    build = pwd.getpwnam(BUILD_USER)
    for directory, _, filenames in os.walk(release):
        os.chown(directory, build.pw_uid, build.pw_gid)
        for name in filenames:
            os.chown(Path(directory) / name, build.pw_uid, build.pw_gid)
    as_user(BUILD_USER, [sys.executable, '-m', 'venv', release / '.venv'], cwd=release)
    as_user(BUILD_USER, [release / '.venv/bin/pip', 'install', '--disable-pip-version-check',
                        '-r', release / 'requirements.txt'], cwd=release)
    # Static compilation receives synthetic build-only settings, not host secrets.
    build_env = {'ADMIN_SECRET_KEY': 'static-build-only-non-secret-' * 3,
                 'ADMIN_MFA_ENCRYPTION_KEY': 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',
                 'ADMIN_GITHUB_CLIENT_ID': 'build-only', 'ADMIN_GITHUB_CLIENT_SECRET': 'build-only'}
    as_user(BUILD_USER, [release / '.venv/bin/python', 'manage.py', 'collectstatic', '--noinput'],
            cwd=release, env=build_env)
    (release / 'revision.env').write_text(f'ADMIN_SOURCE_REVISION={revision}\n')
    seal_tree(release)
    environment['ADMIN_SOURCE_REVISION'] = revision
    previous = (ROOT / 'current').resolve() if (ROOT / 'current').is_symlink() else None
    # This release only adds application-owned tables. Never reverse migrations automatically.
    as_user(APP_USER, [release / '.venv/bin/python', 'manage.py', 'migrate', '--noinput'],
            cwd=release, env=environment)
    as_user(APP_USER, [release / '.venv/bin/python', 'manage.py', 'check', '--deploy', '--fail-level', 'WARNING'],
            cwd=release, env=environment)
    for name in UNIT_NAMES:
        target = UNIT_DIR / name
        # Only replace units carrying our fixed application ownership marker.
        if target.exists() and 'Oracle' not in target.read_text():
            raise ValueError(f'Foreign systemd unit exists: {name}')
        shutil.copyfile(SOURCE / 'deploy' / name, target)
        target.chmod(0o644)
    switch(release)
    command(['systemctl', 'daemon-reload'])
    try:
        command(['systemctl', 'restart', UNIT_NAMES[0]])
        if not healthy():
            raise ValueError('Application failed local health verification')
    except (ValueError, subprocess.CalledProcessError):
        if previous is not None:
            switch(previous)
            command(['systemctl', 'restart', UNIT_NAMES[0]])
        else:
            subprocess.run(['systemctl', 'stop', UNIT_NAMES[0]], check=False)
        raise
    if previous is not None:
        (ROOT / 'previous').unlink(missing_ok=True)
        (ROOT / 'previous').symlink_to(previous)
    command(['systemctl', 'enable', UNIT_NAMES[0], UNIT_NAMES[2]])
    command(['systemctl', 'restart', UNIT_NAMES[2]])
    print('ORACLE_ADMIN=ACTIVE_LOOPBACK_ONLY')
    print('Review deploy/Caddyfile and merge its dedicated host block into your existing Caddy config.')
    print('Then validate/reload Caddy; this installer does not overwrite any existing web-server config.')


def rollback():
    previous = ROOT / 'previous'
    if not previous.is_symlink():
        raise ValueError('No previous successful application version')
    target = previous.resolve()
    if target.parent != (ROOT / 'releases').resolve() or not (target / 'manage.py').is_file():
        raise ValueError('Invalid previous release')
    current = (ROOT / 'current').resolve()
    switch(target)
    command(['systemctl', 'restart', UNIT_NAMES[0]])
    if not healthy():
        switch(current); command(['systemctl', 'restart', UNIT_NAMES[0]])
        raise ValueError('Rollback health check failed; current version restored')
    print('ORACLE_ADMIN=ROLLED_BACK; database and host secrets retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('preflight', 'install', 'rollback'))
    parser.add_argument('--revision')
    options = parser.parse_args()
    if options.operation == 'preflight':
        print(json.dumps(preflight(), indent=2)); return
    if os.geteuid() != 0:
        raise SystemExit('Host administrator privileges are required for registration or rollback')
    os.umask(0o077)
    if options.operation == 'install':
        revision = options.revision
        if revision is None and (SOURCE / 'SOURCE_REVISION').is_file():
            revision = (SOURCE / 'SOURCE_REVISION').read_text().strip()
        install(revision or '')
    else:
        rollback()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
