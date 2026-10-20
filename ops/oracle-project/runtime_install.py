"""Pinned upstream runtime for older apt hosts; never replace system Python."""
import hashlib
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

PYTHON_ROOT = Path('/opt/oracle-proxy-python-3.12.15')
PYTHON = PYTHON_ROOT / 'python/bin/python3.12'
ASSETS = {
    'aarch64': (
        'aarch64', 'arm64',
        '9467a99bacc7d90b64b02de7fa9ecfc99b72905e64e74f7ff6b460ad95cfed5a',
        'ca8ae5a50439642d7672344b4ec64e47cbddf81beb5da302420a78522eb5a47e'),
    'x86_64': (
        'x86_64', 'amd64',
        '178d3d83b6e8e99285a65d3fce9c16b87952cc5efdb4d1a0e3ff3be18ff0fc9c',
        'a22b914ffd1958da42bc7ab13b7b62c6100634e0798ab594891d2d61d53ba749'),
}


def seal_permissions(root=PYTHON_ROOT):
    if not root.exists(): return
    if root.is_symlink(): raise ValueError('RUNTIME_ROOT_LINK_REJECTED')
    for directory, directories, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / name for name in directories + files]:
            info = path.lstat()
            if info.st_uid != os.geteuid(): raise ValueError('RUNTIME_OWNER_REJECTED')
            if path.is_symlink():
                if not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError('RUNTIME_LINK_REJECTED')
            elif path.is_dir(): path.chmod(0o755)
            elif path.is_file(): path.chmod(0o755 if info.st_mode & 0o111 else 0o644)
            else: raise ValueError('RUNTIME_FILE_TYPE_REJECTED')


def fetch_verified(url, checksum, destination):
    request = urllib.request.Request(url, headers={'User-Agent': 'Oracle-Project-Runtime'})
    digest = hashlib.sha256(); size = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as output:
        if not response.url.startswith('https://'):
            raise ValueError('RUNTIME_HTTPS_REQUIRED')
        while True:
            block = response.read(1024 * 1024)
            if not block: break
            size += len(block)
            if size > 100 * 1024 * 1024: raise ValueError('RUNTIME_DOWNLOAD_TOO_LARGE')
            digest.update(block); output.write(block)
    if digest.hexdigest() != checksum:
        destination.unlink()
        raise ValueError('RUNTIME_CHECKSUM_MISMATCH')


def extract_python(archive_path, destination):
    # Fresh private staging directory. Create links last so no member can write through one.
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers(); seen = set(); total = 0
        if len(members) > 20000: raise ValueError('RUNTIME_ARCHIVE_TOO_MANY_ENTRIES')
        for item in members:
            path = PurePosixPath(item.name)
            if (path.is_absolute() or not path.parts or path.parts[0] != 'python' or
                    '..' in path.parts or '\\' in item.name or item.name.rstrip('/') in seen or
                    not (item.isdir() or item.isfile() or item.issym())):
                raise ValueError('RUNTIME_ARCHIVE_PATH_REJECTED')
            seen.add(item.name.rstrip('/')); total += item.size
            if total > 400 * 1024 * 1024: raise ValueError('RUNTIME_ARCHIVE_TOO_LARGE')
            if item.issym():
                target = (destination / item.name).parent / item.linkname
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise ValueError('RUNTIME_ARCHIVE_LINK_REJECTED')
        links = {PurePosixPath(i.name) for i in members if i.issym()}
        for item in members:
            path = PurePosixPath(item.name)
            if any(parent in links for parent in path.parents):
                raise ValueError('RUNTIME_ARCHIVE_LINK_PARENT_REJECTED')
            target = destination / item.name
            if item.isdir(): target.mkdir(parents=True, exist_ok=True); target.chmod(0o755)
            elif item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
        for item in members:
            if item.issym():
                target = destination / item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(item.linkname)
    seal_permissions(destination)


def install():
    asset = ASSETS.get(platform.machine())
    if asset is None: raise ValueError('RUNTIME_ARCHITECTURE_UNSUPPORTED')
    python_arch, deb_arch, python_hash, caddy_hash = asset
    with tempfile.TemporaryDirectory(prefix='oracle-runtime-') as temporary:
        temporary = Path(temporary)
        if not PYTHON.exists():
            if PYTHON_ROOT.exists() or PYTHON_ROOT.is_symlink():
                raise ValueError('RUNTIME_INSTALL_PATH_OCCUPIED')
            archive = temporary / 'python.tar.gz'
            fetch_verified('https://github.com/astral-sh/python-build-standalone/releases/download/'
                           '20261013/cpython-3.12.15%2B20261013-' + python_arch +
                           '-unknown-linux-gnu-install_only_stripped.tar.gz', python_hash, archive)
            with tempfile.TemporaryDirectory(prefix='.oracle-python-', dir='/opt') as staging:
                stage = Path(staging)
                extract_python(archive, stage)
                subprocess.run([str(stage / 'python/bin/python3.12'), '-I', '-c',
                                'import ssl,sqlite3,venv,ensurepip; assert ssl.OPENSSL_VERSION'], check=True)
                stage.chmod(0o755)
                os.rename(stage, PYTHON_ROOT)
                # TemporaryDirectory must still have a harmless directory to clean up.
                stage.mkdir()
        if not shutil.which('caddy'):
            package = temporary / 'caddy.deb'
            fetch_verified('https://github.com/caddyserver/caddy/releases/download/v2.11.7/'
                           'caddy_2.11.7_linux_' + deb_arch + '.deb', caddy_hash, package)
            subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', str(package)],
                           check=True, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive',
                                            'NEEDRESTART_MODE': 'l'})
    print('PROJECT_PINNED_RUNTIME=Python-3.12.15_Caddy-2.11.7_READY')
