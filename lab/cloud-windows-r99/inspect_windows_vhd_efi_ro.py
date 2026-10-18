"""R99 read-only inspection of an OFFLINE official Microsoft evaluation disk EFI boot paths.

This inspector prints only booleans about expected EFI loader file paths.
No guest execution, host network, WFP, driver, signing or Windows policy change.
Attaches only an exact job-owned sparse .raw disk via a RO Linux loop device.
"""
from pathlib import Path
import argparse
import os
import re
import subprocess
import time

LOOP = re.compile(r"^/dev/loop[0-9]+$")
EFI_FILES = ("EFI/Microsoft/Boot/bootmgfw.efi", "EFI/Microsoft/Boot/BCD",
             "EFI/Boot/bootx64.efi")


def run(*argv, check=True):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    if check and p.returncode:
        raise RuntimeError("R99_UEFI_HOST_TOOL_DENIED")
    return p


def inspect(image: Path, mountpoint: Path):
    if image.suffix != ".raw" or not image.is_file() or image.stat().st_size < 2**31:
        raise ValueError("unexpected disposable RAW image")
    if not mountpoint.is_dir() or any(mountpoint.iterdir()):
        raise ValueError("mount directory not empty")
    loop = ""
    mounted = False
    try:
        loop = run("sudo", "-n", "losetup", "--find", "--show", "--partscan",
                   "--read-only", str(image)).stdout.strip()
        if not LOOP.fullmatch(loop):
            raise RuntimeError("R99_UNEXPECTED_LOOP_DEVICE")
        backing = run("sudo", "-n", "losetup", "-l", "-n", "-O", "BACK-FILE", loop).stdout.strip()
        if backing != str(image):
            raise RuntimeError("R99_FOREIGN_BACKING_REFUSED")
        time.sleep(.35)
        lines = run("sudo", "-n", "lsblk", "-nr", "-o", "PATH,FSTYPE", loop).stdout.splitlines()
        efi = [parts[0] for line in lines if (parts := line.split()) and len(parts) == 2
               and parts[0].startswith(loop + "p") and parts[1].lower() in ("vfat", "fat32")]
        if not (1 <= len(efi) <= 5):
            print("R99_EFI_VFAT_PARTITION_COUNT_OUT_OF_ALLOWED_RANGE_DENY")
            return False
        seen = {name: False for name in EFI_FILES}
        for part in efi:
            if not re.fullmatch(re.escape(loop) + r"p[0-9]{1,2}", part):
                raise RuntimeError("R99_FOREIGN_EFI_PARTITION_REFUSED")
            if run("sudo", "-n", "mount", "-t", "vfat", "-o",
                   "ro,nosuid,nodev,noexec", part, str(mountpoint), check=False).returncode:
                continue
            mounted = True
            try:
                for file in EFI_FILES:
                    p = mountpoint / file
                    if p.is_file() and not p.is_symlink() and 1024 < p.stat().st_size < 100*1024**2:
                        seen[file] = True
            finally:
                run("sudo", "-n", "umount", str(mountpoint))
                mounted = False
        print("R99_EFI_MICROSOFT_BOOTMGR_PRESENT=" + str(seen[EFI_FILES[0]]).lower())
        print("R99_EFI_MICROSOFT_BCD_PRESENT=" + str(seen[EFI_FILES[1]]).lower())
        print("R99_EFI_FALLBACK_BOOTX64_PRESENT=" + str(seen[EFI_FILES[2]]).lower())
        # No validated signed Windows loader + BCD -> nothing meaningful to
        # boot. A missing generic UEFI fallback is independently relevant
        # but cannot by itself prove the firmware always lacks another route.
        return seen[EFI_FILES[0]] and seen[EFI_FILES[1]]
    finally:
        if mounted:
            run("sudo", "-n", "umount", str(mountpoint))
        if loop and LOOP.fullmatch(loop):
            v = run("sudo", "-n", "losetup", "-l", "-n", "-O", "BACK-FILE", loop, check=False)
            if v.returncode == 0 and v.stdout.strip() == str(image):
                run("sudo", "-n", "losetup", "-d", loop)
            else:
                raise RuntimeError("R99_UEFI_LOOP_OWNER_UNKNOWN_NO_FOREIGN_DELETE")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--mount", type=Path, required=True)
    a = p.parse_args()
    try:
        return 0 if inspect(a.raw.resolve(), a.mount.resolve()) else 6
    except Exception as e:
        print("R99_UEFI_READONLY_INSPECTION_DENY_" + type(e).__name__)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
