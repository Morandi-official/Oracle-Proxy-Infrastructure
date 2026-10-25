"""Publish one hash-pinned, reviewed public diagnostic; never execute its bytes."""
import hashlib
import os
from pathlib import Path
import tempfile

SOURCE=Path(__file__).resolve().parents[2]/'clients/windows/diagnostics/Test-LegacyNativePorts.ps1'
DIGEST='71236868b665e188eef63937e7c63531a5bffdc6aed475150fc9782be599b564'
NAME='Test-LegacyNativePorts-'+DIGEST[:12]+'.ps1'
ROOT=Path('/var/lib/oracle-proxy-downloads/diagnostics')


def install(source=SOURCE,root=ROOT):
    if source.is_symlink():raise ValueError('DIAGNOSTIC_SOURCE_LINK_REJECTED')
    body=source.read_bytes()
    if len(body)>16384 or hashlib.sha256(body).hexdigest()!=DIGEST:raise ValueError('DIAGNOSTIC_SOURCE_DIGEST_MISMATCH')
    for parent in (root.parent,root):
        if parent.is_symlink():raise ValueError('DIAGNOSTIC_ROOT_LINK_REJECTED')
        if not parent.exists():parent.mkdir(mode=0o755)
        if not parent.is_dir() or parent.stat().st_uid!=os.geteuid() or parent.stat().st_mode&0o022:raise ValueError('DIAGNOSTIC_ROOT_WRITABLE')
        parent.chmod(0o755) # Root bridge uses umask077; this directory contains public assets.
    destination=root/NAME
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file() or destination.stat().st_uid!=os.geteuid() or destination.stat().st_mode&0o022 or destination.read_bytes()!=body:raise ValueError('DIAGNOSTIC_EXISTING_MISMATCH')
    else:
        fd,name=tempfile.mkstemp(prefix='.network-diagnostic-',dir=root.parent.parent)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.chmod(name,0o644);os.replace(name,destination)
        finally:
            if os.path.exists(name):os.unlink(name)
    print('PROJECT_NETWORK_DIAGNOSTIC=VERIFIED; SHA256='+DIGEST)


def verify_public():
    import urllib.request
    url='https://vpn-admin.morandi.dpdns.org/downloads/diagnostics/'+NAME
    with urllib.request.urlopen(url,timeout=15) as response:
        body=response.read(16385)
        if response.headers.get('Content-Disposition','').lower()!='attachment' or response.headers.get_content_type()!='application/octet-stream':raise ValueError('PUBLIC_DIAGNOSTIC_DOWNLOAD_HEADERS_MISSING')
        if response.geturl()!=url or len(body)>16384 or hashlib.sha256(body).hexdigest()!=DIGEST:raise ValueError('PUBLIC_DIAGNOSTIC_DIGEST_MISMATCH')
    print('PUBLIC_NETWORK_DIAGNOSTIC=SHA256_VERIFIED')
