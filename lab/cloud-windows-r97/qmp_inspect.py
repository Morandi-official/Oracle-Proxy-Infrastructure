"""R97 host-only QMP control; never contacts guest network or runs in Windows."""
import hashlib
import json
import os
import socket
import sys


def control(sockname: str, action: str, target: str = "") -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect(sockname)
        stream = sock.makefile("rwb", buffering=0)
        def next_reply():
            while True:
                obj = json.loads(stream.readline())
                if "return" in obj or "error" in obj:
                    if "error" in obj:
                        raise RuntimeError("QMP command not accepted")
                    return obj["return"]
        greeting = json.loads(stream.readline())
        if "QMP" not in greeting:
            raise RuntimeError("not QMP")
        stream.write(b'{"execute":"qmp_capabilities"}\n')
        next_reply()
        def send(name, arguments=None):
            cmd = {"execute": name}
            if arguments is not None:
                cmd["arguments"] = arguments
            stream.write((json.dumps(cmd) + "\n").encode())
            return next_reply()
        if action in ("screenshot", "reset"):
            status = send("query-status")
            if status.get("status") != "running":
                raise RuntimeError("QEMU guest virtual machine not running")
            print("R97_QEMU_VM_RUNNING_STATUS_CONFIRMED")
        if action == "screenshot":
            if not os.path.realpath(target).startswith(os.path.realpath(os.environ["RUNNER_TEMP"]) + "/"):
                raise RuntimeError("unexpected screenshot path")
            send("human-monitor-command", {"command-line": "screendump " + target})
            with open(target, "rb") as f:
                data = f.read(8_000_000)
            if not data.startswith(b"P6\n") or len(data) < 10000:
                raise RuntimeError("guest framebuffer unavailable")
            print("R97_FRAMEBUFFER_IMAGE_SHA256_PREFIX=" +
                  hashlib.sha256(data).hexdigest()[:16])
            print("R97_DISPLAY_CONTENT_IS_NOT_PROOF_OF_WINDOWS_KERNEL_BOOT")
        elif action == "reset":
            send("system_reset")
            print("R97_QMP_HOST_HARDWARE_RESET_SENT")
        elif action == "quit":
            send("quit")
            print("R97_QMP_GUEST_TERMINATION_REQUESTED")
        else:
            raise ValueError("unknown action")


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit(2)
    control(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else "")
