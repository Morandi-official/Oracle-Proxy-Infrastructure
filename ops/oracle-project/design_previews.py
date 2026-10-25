"""Publish four pinned, public design PNGs from this reviewed source revision."""
import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / 'docs/design-previews/20261025'
ROOT = Path('/var/lib/oracle-proxy-downloads')
VERSION = 'design-previews-20261025'
PINS = {'OracleProxy-design-A-20261025.png': {'size': 1512450, 'sha256': 'eb34259afa1f9e82db2500f742c795c6f25fdcf8e7c8ba123b49dc20c29dbdc6'}, 'OracleProxy-design-B-20261025.png': {'size': 1610093, 'sha256': 'b98df426ad7900c26696684d6084f0af1d110d794cb13207998286aa10c38fb7'}, 'OracleProxy-design-C-20261025.png': {'size': 1486866, 'sha256': 'b4263cde68f216cd9da77c43889bdde7407830da4055ef8c6281751c10a50a7a'}, 'OracleProxy-design-D-20261025.png': {'size': 1457258, 'sha256': '92cc4f98f33c6959dd1a1df2f0c5f42c5cc337b0ba0bb0d1ed6e89d61ec0e684'}}


def regular(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('PREVIEW_REGULAR_FILE_REQUIRED')
    return path.read_bytes()


def install(root=ROOT, source=SOURCE):
    bodies={}
    for name,item in PINS.items():
        body=regular(source/name)
        if (len(body)!=item['size'] or len(body)>5*1024*1024 or
                not body.startswith(b'\x89PNG\r\n\x1a\n') or hashlib.sha256(body).hexdigest()!=item['sha256']):
            raise ValueError('PREVIEW_DIGEST_MISMATCH')
        bodies[name]=body
    for parent in (root.parent,root):
        if parent.is_symlink():raise ValueError('PREVIEW_ROOT_LINK_REJECTED')
        if not parent.exists():parent.mkdir(mode=0o755)
        info=parent.stat()
        if not parent.is_dir() or info.st_uid!=os.geteuid() or info.st_mode & 0o022:
            raise ValueError('PREVIEW_ROOT_WRITABLE')
    target=root/VERSION
    if target.is_symlink():raise ValueError('PREVIEW_VERSION_LINK_REJECTED')
    if target.exists():
        info=target.stat()
        if (not target.is_dir() or info.st_uid!=os.geteuid() or info.st_mode & 0o022 or
                {p.name for p in target.iterdir()}!=set(PINS)):
            raise ValueError('PREVIEW_EXISTING_VERSION_REJECTED')
        if any(regular(target/name)!=body for name,body in bodies.items()):
            raise ValueError('PREVIEW_EXISTING_DIGEST_MISMATCH')
        print('PROJECT_DESIGN_PREVIEWS=ALREADY_VERIFIED');return
    stage=Path(tempfile.mkdtemp(prefix='.oracle-design-stage-',dir=root.parent))
    try:
        for name,body in bodies.items():
            path=stage/name;path.write_bytes(body);path.chmod(0o644)
        stage.chmod(0o755)
        os.rename(stage,target)
        print('PROJECT_DESIGN_PREVIEWS=VERIFIED_COUNT_4')
    finally:
        if stage.exists():shutil.rmtree(stage)
