"""Read System.evtx from OFFLINE RAW clone of an official guest VHD/overlay.

Uses an exact-owned synthetic /dev/loopN RO, enumerates its NTFS partitions,
mounts only them read-only, copies bounded System.evtx without guest execution.
Never mutates mounted guest filesystem, routes, WFP, kernel security, or other
host disks. The image was already safely qemu-img converted to sparse raw.
"""
from __future__ import annotations
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import time

LOOP = re.compile(r"^/dev/loop[0-9]+$")
MAX_PARTITIONS = 16
MAX_EVENTS = 128 * 1024 * 1024
EVTX = Path("Windows/System32/winevt/Logs/System.evtx")

def run(*argv: str, check=True):
    p=subprocess.run(list(argv),text=True,capture_output=True,timeout=70)
    if check and p.returncode:
        raise RuntimeError("R99_OFFLINE_OS_DEVICE_TOOL_FAILED_"+argv[0].replace("/","_"))
    return p

def extract(image: Path, target: Path, mountpath: Path) -> bool:
    if not image.is_file() or image.suffix != ".raw" or image.stat().st_size < 2*1024**3:
        raise ValueError("unapproved raw guest disk shape")
    if not mountpath.exists() or any(mountpath.iterdir()):
        raise ValueError("mount directory must preexist empty")
    loop=""
    mounted=False
    try:
        x=run("sudo","-n","losetup","--find","--show","--partscan","--read-only",str(image))
        loop=x.stdout.strip()
        if not LOOP.fullmatch(loop):
            raise RuntimeError("R99_REFUSED_NON_LOOP_DEVICE")
        # The device must be owned by the exact raw image we just created.
        backing=run("sudo","-n","losetup","-l","-n","-O","BACK-FILE",loop).stdout.strip()
        if backing != str(image):
            raise RuntimeError("R99_REFUSED_FOREIGN_LOOP_BACKING")
        time.sleep(0.35)
        devices=run("sudo","-n","lsblk","-nr","-o","PATH,FSTYPE",loop).stdout.splitlines()
        candidates=[]
        for line in devices:
            parts=line.split()
            if len(parts)==2 and parts[0].startswith(loop+"p") and re.fullmatch(r"ntfs|ntfs3",parts[1],re.I):
                candidates.append(parts[0])
        if not candidates or len(candidates)>MAX_PARTITIONS:
            print("R99_OFFLINE_LOOP_WINDOWS_NTFS_VOLUME_NOT_FOUND_DENY")
            return False
        print("R99_OFFLINE_NTFS_VOLUME_CANDIDATES="+str(len(candidates)))
        for dev in candidates:
            if not re.fullmatch(re.escape(loop)+r"p[0-9]{1,2}",dev):
                raise RuntimeError("R99_REFUSED_FOREIGN_PARTITION")
            ntfs=run("sudo","-n","mount","-t","ntfs3","-o","ro",dev,str(mountpath),check=False)
            if ntfs.returncode:
                ntfs=run("sudo","-n","mount","-t","ntfs-3g","-o","ro",dev,str(mountpath),check=False)
            if ntfs.returncode:
                continue
            mounted=True
            try:
                path=mountpath/EVTX
                if not path.is_file() or path.is_symlink():
                    continue
                size=path.stat().st_size
                if not 4096<=size<=MAX_EVENTS:
                    continue
                run("sudo","-n","cp","--",str(path),str(target))
                run("sudo","-n","chown",str(os.getuid())+":"+str(os.getgid()),str(target))
                if target.stat().st_size!=size:
                    raise RuntimeError("R99_INCOMPLETE_OFFLINE_EVENTLOG_COPY")
                print("R99_OFFLINE_LOOP_GUEST_SYSTEM_EVTX_EXTRACTED_READ_ONLY")
                return True
            finally:
                run("sudo","-n","umount",str(mountpath))
                mounted=False
        print("R99_OFFLINE_LOOP_WINDOWS_SYSTEM_EVENTLOG_UNAVAILABLE_DENY")
        return False
    finally:
        if mounted:
            run("sudo","-n","umount",str(mountpath))
        if loop and LOOP.fullmatch(loop):
            backing=run("sudo","-n","losetup","-l","-n","-O","BACK-FILE",loop,check=False)
            if backing.returncode==0 and backing.stdout.strip()==str(image):
                run("sudo","-n","losetup","-d",loop)
            else:
                raise RuntimeError("R99_LOOP_OWNERSHIP_UNVERIFIABLE_NO_FOREIGN_DELETE")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--raw",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--mount",type=Path,required=True)
    args=p.parse_args()
    try:
        return 0 if extract(args.raw.resolve(),args.output.resolve(),args.mount.resolve()) else 6
    except Exception as e:
        print("R99_OFFLINE_LOOP_READ_DENY_CLASS="+type(e).__name__)
        return 6

if __name__=="__main__":
    raise SystemExit(main())
