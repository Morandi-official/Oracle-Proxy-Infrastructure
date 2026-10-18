"""R99 enumerate candidate NTFS partitions and read System.evtx without OS auto-mount.

Only powered-off official evaluation VHD/owned qcow2, no guest execution,
no mounting RW, no guest networking, no payload logs to public CI.
"""
import argparse
from pathlib import Path
import re
import subprocess

ALLOWED_FMT={"vpc","vhdx","raw","qcow2"}
EVENT="/Windows/System32/winevt/Logs/System.evtx"
FS_RE=re.compile(r"^(/dev/(?:sd[a-z][0-9]{1,2}|vd[a-z][0-9]{1,2}|nvme[0-9]n[0-9]p[0-9]{1,2})):\s+(ntfs|ntfs-3g)\s*$")

def run(args):
    return subprocess.run(args, text=True, capture_output=True,
                          check=False, timeout=100)

def evidence_readonly(img: Path, fmt: str, output: Path) -> bool:
    if fmt not in ALLOWED_FMT or not img.is_file():
        raise ValueError("unapproved disk image or format")
    base=["guestfish","--ro","--format="+fmt,"-a",str(img),"run",":"]
    response=run(base+["list-filesystems"])
    if response.returncode != 0:
        print("R99_GUESTFS_FILESYSTEM_ENUMERATION_UNAVAILABLE_DENY")
        return False
    allowed=[]
    for line in response.stdout.splitlines():
        match=FS_RE.fullmatch(line.strip())
        if match:
            allowed.append(match.group(1))
    if not allowed or len(allowed)>12:
        print("R99_NO_ALLOWLISTED_NTFS_PARTITION_FOUND_DENY")
        return False
    print("R99_READONLY_NTFS_PARTITIONS_COUNT="+str(len(allowed)))
    for dev in allowed:
        found=run(base+["mount-ro",dev,"/",":","exists",EVENT])
        if found.returncode or found.stdout.strip()!="true":
            continue
        result=run(base+["mount-ro",dev,"/",":","download",EVENT,str(output)])
        if result.returncode==0 and output.is_file() and (
            4096 <= output.stat().st_size <= 128*1024*1024
        ):
            print("R99_OFFLINE_GUEST_SYSTEM_EVTX_EXTRACTED_READ_ONLY")
            return True
        output.unlink(missing_ok=True)
    print("R99_NO_READABLE_OFFLINE_WINDOWS_SYSTEM_EVTX_DENY")
    return False

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--format",choices=sorted(ALLOWED_FMT),required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    try:
        return 0 if evidence_readonly(args.image,args.format,args.output) else 6
    except (ValueError,subprocess.TimeoutExpired,PermissionError) as e:
        print("R99_GUESTFS_INSPECTION_FAIL_CLASS_"+type(e).__name__)
        return 6

if __name__=="__main__":
    raise SystemExit(main())
