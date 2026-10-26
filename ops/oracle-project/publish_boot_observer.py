"""Publish only the pinned read-only owner reboot observer; never execute it."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile

SOURCE=Path(__file__).resolve().parents[2]/'ops/windows-boot/Test-OracleProxyBoot.ps1'
DIGEST='037eb62575b2d8cebff0d780c59b667169731eaceb172a6294731303f84b285e'
ROOT=Path('/var/lib/oracle-proxy-downloads/diagnostics')
NAME='OracleProxy-Boot-rc20-'+DIGEST[:12]+'.ps1'


def trusted(path,directory=False):
    value=path.lstat()
    if path.is_symlink() or value.st_uid!=os.geteuid() or value.st_mode&0o022 or (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode)):
        raise ValueError('BOOT_OBSERVER_OWNED_PATH_REQUIRED')


def install():
    trusted(SOURCE)
    body=SOURCE.read_bytes()
    if not 0<len(body)<=65536 or hashlib.sha256(body).hexdigest()!=DIGEST:
        raise ValueError('BOOT_OBSERVER_PIN_REQUIRED')
    body.decode('ascii')
    trusted(ROOT.parent,True)
    if not ROOT.exists():ROOT.mkdir(mode=0o755)
    trusted(ROOT,True)
    target=ROOT/NAME
    if target.exists() or target.is_symlink():
        trusted(target)
        if target.read_bytes()!=body:raise ValueError('BOOT_OBSERVER_IMMUTABLE_PATH_CONFLICT')
    else:
        fd,name=tempfile.mkstemp(dir=ROOT,prefix='.boot-observer-')
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.chmod(name,0o644);os.replace(name,target)
        finally:
            if os.path.exists(name):os.unlink(name)
    print('BOOT_OBSERVER_PUBLICATION=VERIFIED; NAME='+NAME+'; SHA256='+DIGEST+'; BYTES='+str(len(body)))
