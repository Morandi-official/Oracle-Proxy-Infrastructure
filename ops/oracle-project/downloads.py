"""Mirror exact public, accepted release bytes; never execute downloaded files."""
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path('/var/lib/oracle-proxy-downloads')
MANIFEST = Path(__file__).with_name('downloads-current.json')
UPSTREAM = 'https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/releases/download/'


def manifest():
    value = json.loads(MANIFEST.read_text())
    if (not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+',str(value.get('version',''))) or
            not re.fullmatch(r'[a-f0-9]{40}',str(value.get('source_revision','')))):
        raise ValueError('PINNED_DOWNLOAD_MANIFEST_REQUIRED')
    prefix='OracleProxy-'+value['version'][1:]+'-win-x64-'+value['source_revision'][:12]
    if (len(value['assets']) != 4 or {a['name'] for a in value['assets']} !=
            {prefix+'.zip',prefix+'-source.zip','BUILD.json','SHA256SUMS.txt'}):
        raise ValueError('PINNED_DOWNLOAD_MANIFEST_REQUIRED')
    for item in value['assets']:
        if (type(item['size']) is not int or not 0 < item['size'] <= 512*1024*1024 or
                len(item['sha256']) != 64 or any(c not in '0123456789abcdef' for c in item['sha256'])):
            raise ValueError('PINNED_ASSET_REQUIRED')
    return value


def matches(path, item):
    if not path.exists() or path.is_symlink(): return False
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o022 or info.st_size != item['size']: return False
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''): digest.update(block)
    return digest.hexdigest() == item['sha256']


def fetch(url, path, item):
    digest = hashlib.sha256(); size = 0; deadline = time.monotonic()+300
    try:
        request = urllib.request.Request(url, headers={'User-Agent':'Oracle-Proxy-Pinned-Downloads'})
        with urllib.request.urlopen(request, timeout=30) as response, path.open('xb') as output:
            final = urllib.parse.urlsplit(response.url)
            if final.scheme != 'https' or final.hostname not in ('github.com','release-assets.githubusercontent.com'):
                raise ValueError('UNTRUSTED_DOWNLOAD_REDIRECT')
            while True:
                block = response.read(1024*1024)
                if not block: break
                size += len(block)
                if size > item['size'] or time.monotonic() > deadline: raise ValueError('DOWNLOAD_LIMIT_EXCEEDED')
                digest.update(block); output.write(block)
        if size != item['size'] or digest.hexdigest() != item['sha256']:
            raise ValueError('DOWNLOAD_DIGEST_MISMATCH')
        path.chmod(0o644)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def install(root=ROOT):
    value = manifest()
    # Only the root project operator can write these static public artifacts.
    for parent in (root.parent, root):
        if parent.is_symlink(): raise ValueError('DOWNLOAD_ROOT_LINK_REJECTED')
        if not parent.exists(): parent.mkdir(mode=0o755)
        info = parent.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022: raise ValueError('DOWNLOAD_ROOT_WRITABLE')
    root.chmod(0o755)
    target = root / value['version']
    if target.is_symlink(): raise ValueError('DOWNLOAD_VERSION_LINK_REJECTED')
    if target.exists():
        if target.stat().st_uid != os.geteuid() or target.stat().st_mode & 0o022:
            raise ValueError('DOWNLOAD_VERSION_WRITABLE')
        if not target.is_dir() or {p.name for p in target.iterdir()} != {a['name'] for a in value['assets']}:
            raise ValueError('EXISTING_MIRROR_REJECTED')
        if not all(matches(target/a['name'],a) for a in value['assets']): raise ValueError('EXISTING_MIRROR_DIGEST_MISMATCH')
        target.chmod(0o755)
        for path in target.iterdir(): path.chmod(0o644)
        print('PROJECT_DOWNLOAD_MIRROR=ALREADY_VERIFIED'); return
    # Stage outside the public document root; partial files are never served.
    stage = Path(tempfile.mkdtemp(prefix='.oracle-proxy-downloads-stage-',dir=root.parent))
    try:
        for item in value['assets']:
            fetch(UPSTREAM+value['version']+'/'+item['name'], stage/item['name'], item)
        stage.chmod(0o755)
        os.rename(stage,target)
        print('PROJECT_DOWNLOAD_MIRROR=VERIFIED '+value['version'])
    finally:
        if stage.exists(): shutil.rmtree(stage)
