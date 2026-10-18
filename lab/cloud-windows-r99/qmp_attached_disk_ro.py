"""R99 host-only QMP evidence the running disposable QEMU has the right disk.

This is virtual-hardware inventory, NOT proof of Windows OS startup.
No qmp modify/reset/guest commands here and no image paths are logged.
"""
import argparse
import json
import os
from pathlib import Path
import socket


def check(socket_path: Path, expected_overlay: Path) -> bool:
    if not expected_overlay.is_file() or expected_overlay.suffix != ".qcow2":
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(12)
        s.connect(str(socket_path))
        io=s.makefile("rwb", buffering=0)
        greeting=json.loads(io.readline())
        if "QMP" not in greeting:
            return False
        def command(op):
            io.write((json.dumps({"execute":op})+"\n").encode())
            for _ in range(64):
                line=io.readline()
                if not line:
                    raise RuntimeError("qmp disconnected")
                result=json.loads(line)
                if "error" in result:
                    raise RuntimeError("QMP read-only query denied")
                if "return" in result:
                    return result["return"]
            raise RuntimeError("QMP response bound exceeded")
        command("qmp_capabilities")
        status=command("query-status")
        if status.get("status")!="running":
            return False
        entries=command("query-block")
        own=os.path.realpath(expected_overlay)
        matches=[]
        for e in entries:
            if not isinstance(e,dict):
                continue
            inserted=e.get("inserted")
            if not isinstance(inserted,dict):
                continue
            candidate=inserted.get("file")
            if isinstance(candidate,str) and os.path.realpath(candidate)==own:
                matches.append(inserted)
        if len(matches)!=1:
            return False
        disk=matches[0]
        image=disk.get("image",{})
        if not isinstance(image,dict):
            return False
        size=image.get("virtual-size",0)
        if not isinstance(size,int) or size<2**31:
            return False
        print("R99_QMP_EXACT_OWNED_VHD_OVERLAY_ATTACHED_PASS")
        print("R99_QMP_RUNNING_VIRTUAL_HARDWARE_ONLY_NOT_WINDOWS_BOOT")
        return True


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--qmp",type=Path,required=True)
    p.add_argument("--expected-overlay",type=Path,required=True)
    opts=p.parse_args()
    try:
        raise SystemExit(0 if check(opts.qmp,opts.expected_overlay) else 6)
    except Exception as ex:
        print("R99_QMP_DISK_INVENTORY_DENY_"+type(ex).__name__)
        raise SystemExit(6)
