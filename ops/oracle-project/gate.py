"""Root bridge: execute only the named repository's current main operations.

Trust boundary: anyone able to update this repository's main can update the
project's root operations. This is intentional CI deployment authority, not a
claim that repository-controlled Python is an OS privilege sandbox.
"""
import fcntl
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

REPOSITORY = 'Morandi-official/Oracle-Proxy-Infrastructure'
ROOT = Path('/var/lib/oracle-project-ops')
OPERATIONS = frozenset(('preflight', 'install-runtime', 'configure', 'deploy', 'enable-https',
                        'status', 'logs', 'start', 'stop', 'restart', 'rollback'))
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download(url, limit):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Oracle-Project-CI-Operations', 'Accept': 'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('REMOTE_CONTENT_TOO_LARGE')
    return body


def verify_main(revision):
    body = download(f'https://api.github.com/repos/{REPOSITORY}/git/ref/heads/main', 16384)
    if json.loads(body).get('object', {}).get('sha') != revision:
        raise ValueError('CURRENT_MAIN_REVISION_REQUIRED')


def validated_members(archive, revision):
    prefix = f'Oracle-Proxy-Infrastructure-{revision}/'
    files = archive.infolist()
    if len(files) > 3000:
        raise ValueError('TOO_MANY_ARCHIVE_ENTRIES')
    total = 0; seen = set(); result = []
    for item in files:
        name = item.filename
        if not name.startswith(prefix) or '\\' in name or '\x00' in name or len(name) > 512:
            raise ValueError('ARCHIVE_PATH_REJECTED')
        relative = name[len(prefix):].rstrip('/')
        parts = PurePosixPath(relative).parts
        if any(p in ('.', '..') for p in parts) or (parts and parts[0].startswith('/')):
            raise ValueError('ARCHIVE_PATH_REJECTED')
        if relative and str(PurePosixPath(relative)) != relative:
            raise ValueError('ARCHIVE_PATH_REJECTED')
        mode = stat.S_IFMT(item.external_attr >> 16)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError('ARCHIVE_LINK_OR_SPECIAL_FILE_REJECTED')
        if item.is_dir():
            continue
        if not relative or relative in seen or item.flag_bits & 1:
            raise ValueError('DUPLICATE_OR_ENCRYPTED_ARCHIVE_REJECTED')
        seen.add(relative)
        total += item.file_size
        if item.file_size > 4 * 1024 * 1024 or total > MAX_EXPANDED:
            raise ValueError('EXPANDED_ARCHIVE_TOO_LARGE')
        result.append((item, relative))
    if 'ops/oracle-project/project_operations.py' not in seen:
        raise ValueError('PROJECT_OPERATIONS_MISSING_FROM_MAIN')
    return result


def source_tree(revision):
    target = ROOT / 'sources' / revision
    if (target / '.verified').is_file():
        return target
    body = download(f'https://codeload.github.com/{REPOSITORY}/zip/{revision}', MAX_ARCHIVE)
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        members = validated_members(archive, revision)
        (ROOT / 'sources').mkdir(mode=0o700, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix='.candidate-', dir=ROOT / 'sources'))
        for item, relative in members:
            path = temporary / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as destination:
                destination.write(archive.read(item))
            path.chmod(0o600)
        (temporary / '.verified').write_text(revision)
        temporary.rename(target)
    return target


def main(arguments):
    if os.geteuid() != 0 or os.environ.get('SUDO_USER') != 'oracle-project-ci':
        raise ValueError('PROJECT_CI_SUDO_IDENTITY_REQUIRED')
    if len(arguments) != 2 or arguments[0] not in OPERATIONS or not re.fullmatch(r'[0-9a-f]{40}', arguments[1]):
        raise ValueError('OPERATION_REJECTED')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid != 0 or ROOT.stat().st_mode & 0o077:
        raise ValueError('UNTRUSTED_OPERATION_DIRECTORY')
    descriptor = os.open(ROOT / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operation, revision = arguments
        verify_main(revision)
        source = source_tree(revision)
        result = subprocess.run([sys.executable, '-I', str(source / 'ops/oracle-project/project_operations.py'),
                                 operation, revision], check=False,
                                env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                     'LANG': 'C.UTF-8', 'HOME': '/root', 'PYTHONDONTWRITEBYTECODE': '1'})
        audit = {'at': int(time.time()), 'operation': operation, 'revision': revision,
                 'exit_code': result.returncode, 'actor': 'oracle-project-ci'}
        audit_fd = os.open(ROOT / 'audit.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(audit_fd, 'w') as stream: stream.write(json.dumps(audit) + '\n')
        return result.returncode
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        # Do not log request bodies, OAuth credentials, environment or remote response bodies.
        print('PROJECT_OPERATION_REJECTED_OR_UNAVAILABLE', file=sys.stderr)
        raise SystemExit(2) from None
