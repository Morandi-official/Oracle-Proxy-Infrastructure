"""Deploy the reviewed port monitor web files without restarting VPN services."""
import json
from pathlib import Path
import stat
import tempfile

import enrollment_console as web

REQUEST_ID = 'native-port-monitor-console-apply'
FILES = tuple(Path(name) for name in (
    'config/urls.py', 'console/views.py', 'console/port_monitor.py',
    'static/console/app.js', 'static/console/style.css', 'templates/dashboard.html',
))


def enabled(operation, request):
    return operation == request.get('operation') == 'deploy' and request.get('request_id') == REQUEST_ID


def digests(directory):
    return {str(path): web.digest(directory / path) if (directory / path).exists() or
            (directory / path).is_symlink() else None for path in FILES}


def dispatch(host, operation, request, revision):
    if not enabled('deploy', request) or operation not in ('preflight', 'deploy'):
        return False
    releases = web.owned(host.ROOT / 'releases', stat.S_ISDIR)
    current = web.active_release(host, releases)
    web.verify_unit(host)
    manifest = json.loads(Path(__file__).with_name('port-console-manifest.json').read_text())
    before, after = manifest['before'], manifest['after']
    if digests(host.SOURCE) != after:
        raise ValueError('PORT_CONSOLE_PAYLOAD_NOT_EXACT')
    observed = digests(current)
    if observed == after and web.ready(host, current):
        print('PROJECT_PORT_MONITOR_CONSOLE=ACTIVE')
        return True
    if observed != before or not web.ready(host, current):
        raise ValueError('PORT_CONSOLE_PREDECESSOR_NOT_VERIFIED')
    if operation == 'preflight':
        print('PROJECT_PORT_MONITOR_CONSOLE=READY')
        return True

    target = web.release_path(releases, revision)
    if not target.exists():
        with tempfile.TemporaryDirectory(prefix='.port-console-', dir=releases) as folder:
            candidate = Path(folder) / revision
            candidate.mkdir()
            web.copy_active(current, candidate, current, current / web.CLIENT_API)
            for path in FILES:
                (candidate / path).write_bytes((host.SOURCE / path).read_bytes())
                (candidate / path).chmod(0o644)
            for name in ('.venv', 'staticfiles'):
                (candidate / name).symlink_to(web.shared_directory(current, name), target_is_directory=True)
            marker = candidate / 'revision.env'
            marker.write_text(f'ADMIN_SOURCE_REVISION={revision}\n')
            marker.chmod(0o644)
            candidate.rename(target)
    web.owned(target, stat.S_ISDIR)
    if digests(target) != after:
        raise ValueError('PORT_CONSOLE_STAGED_PAYLOAD_NOT_EXACT')
    host.require_ingress_release(target)
    environment = host.read_environment()
    environment['ADMIN_SOURCE_REVISION'] = revision
    host.as_user(host.APP_USER, [target / '.venv/bin/python', 'manage.py', 'check', '--deploy', '--fail-level', 'WARNING'],
                 cwd=target, env=environment)
    web.activate(host, target, current)
    print('PROJECT_PORT_MONITOR_CONSOLE=ACTIVE')
    return True
