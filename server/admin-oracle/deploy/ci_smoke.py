"""Actual disposable GitHub-hosted Linux systemd startup/upgrade/failure/rollback test.

No real OAuth credential, user key, tunnel or Oracle server is used.
This harness is omitted from distributable application archives.
"""
import importlib.util
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    if not (os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('GITHUB_REPOSITORY') == 'Morandi-official/Oracle-Proxy-Infrastructure' and
            os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI') == '1'):
        raise SystemExit('Disposable GitHub CI with explicit authorization required')
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('host', source / 'deploy/host.py')
    host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
    if host.ROOT.exists() or host.CONFIG.exists():
        raise SystemExit('Refuse a preexisting application')
    with tempfile.TemporaryDirectory(prefix='oracle-admin-seal-', dir='/tmp') as temporary:
        directory = Path(temporary); outside = directory/'outside'; outside.write_text('synthetic')
        outside.chmod(0o600)
        tree = directory/'tree'; tree.mkdir(); (tree/'link').symlink_to(outside)
        host.seal_tree(tree)
        assert outside.stat().st_mode & 0o777 == 0o600
        os.mkfifo(tree/'pipe')
        try:
            host.seal_tree(tree)
            raise AssertionError('Special build file was accepted')
        except ValueError:
            pass
    try:
        host.prepare_configuration()
    except ValueError:
        pass
    text = host.CONFIG.read_text().replace('REPLACE_WITH_CLIENT_ID', 'ci-synthetic-client')
    text = text.replace('REPLACE_WITH_CLIENT_SECRET', 'ci-synthetic-secret')
    host.CONFIG.write_text(text); host.CONFIG.chmod(0o600)
    first, broken, second = 'a' * 40, 'b' * 40, 'c' * 40
    run([sys.executable, source / 'deploy/host.py', 'install', '--revision', first])
    assert host.healthy()
    assert (host.ROOT / 'current').resolve().name == first
    service_user = subprocess.check_output(['systemctl', 'show', '-p', 'User', '--value',
                                           host.UNIT_NAMES[0]], text=True).strip()
    assert service_user == host.APP_USER
    request = urllib.request.Request(f'http://127.0.0.1:8787/api/status', headers={
        'Host': host.HOST, 'X-Forwarded-Proto': 'https'})
    try:
        urllib.request.urlopen(request, timeout=5)
        raise AssertionError('Unauthenticated service accepted data request')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    assert run(['runuser', '-u', host.APP_USER, '--', 'test', '!', '-w',
                host.ROOT / 'current/manage.py']).returncode == 0
    assert run(['runuser', '-u', host.APP_USER, '--', 'test', '!', '-w',
                host.CONFIG]).returncode == 0
    # Application code is root-owned; service identity can only write its data directory.
    assert (host.ROOT / 'current/manage.py').stat().st_uid == 0
    assert host.STATE.stat().st_uid == pwd.getpwnam(host.APP_USER).pw_uid
    with tempfile.TemporaryDirectory(prefix='oracle-admin-fault-', dir='/tmp') as temporary:
        copy = Path(temporary) / 'candidate'
        shutil.copytree(source, copy, ignore=shutil.ignore_patterns('__pycache__', 'staticfiles', '.venv'))
        (copy / 'config/wsgi.py').write_text("raise RuntimeError('SYNTHETIC_CI_STARTUP_FAILURE')\n")
        result = subprocess.run([sys.executable, str(copy / 'deploy/host.py'), 'install', '--revision', broken],
                                check=False)
        assert result.returncode != 0
        assert (host.ROOT / 'current').resolve().name == first
        assert host.healthy(), 'Previous version was not restored after startup failure'
    run([sys.executable, source / 'deploy/host.py', 'install', '--revision', second])
    assert (host.ROOT / 'current').resolve().name == second
    run([sys.executable, source / 'deploy/host.py', 'rollback'])
    assert (host.ROOT / 'current').resolve().name == first
    assert host.healthy()
    print('DISPOSABLE_SYSTEMD_NONROOT_STARTUP_UPGRADE_FAILED_START_AUTO_RESTORE_EXPLICIT_ROLLBACK=PASS')


if __name__ == '__main__': main()
