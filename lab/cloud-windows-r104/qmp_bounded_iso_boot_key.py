"""Bounded host-only QMP optical boot prompt input for one R104 disposable VM.

Only the fixed Return key is sent, six times within the first twelve seconds.
No arbitrary guest commands, shell, HMP, NIC or Windows configuration.
An acknowledged key event does NOT attest to OS boot or installation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import time

OWNED_PATTERN = re.compile(r"^r104-isolated-install\.[A-Za-z0-9]{8}$")
MAX_REPLY = 8192
KEY_COUNT = 6
KEY_INTERVAL_SEC = 2


def owned_qmp_socket(owned_root: str, runner_temp: str) -> Path:
    if not owned_root or not runner_temp:
        raise ValueError("missing explicit owned runner paths")
    root = Path(owned_root)
    temp = Path(runner_temp)
    if (root.is_symlink() or temp.is_symlink()
            or not OWNED_PATTERN.fullmatch(root.name)
            or root.parent != temp
            or str(root.resolve(strict=True).parent) != str(temp.resolve(strict=True))):
        raise ValueError("QMP directory outside approved temporary runner scope")
    return root / "qmp.sock"


def key_command() -> dict:
    # A fixed boot-media keyboard acknowledgment; no caller-supplied commands.
    return {
        "execute": "send-key",
        "arguments": {
            "keys": [{"type": "qcode", "data": "ret"}],
            "hold-time": 70,
        },
    }


def bounded_read(stream) -> dict:
    line = stream.readline(MAX_REPLY + 1)
    if not line or len(line) > MAX_REPLY:
        raise RuntimeError("QMP response absent or oversized")
    item = json.loads(line)
    if not isinstance(item, dict):
        raise RuntimeError("QMP response must be object")
    return item


def boot_input(qmp_path: Path) -> None:
    metadata = qmp_path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode):
        raise RuntimeError("not exact owned Unix socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(10)
        peer.connect(str(qmp_path))
        stream = peer.makefile("rwb", buffering=0)
        if "QMP" not in bounded_read(stream):
            raise RuntimeError("QMP greeting untrusted")
        next_id = 0

        def send(command: dict):
            nonlocal next_id
            next_id += 1
            cmd = dict(command, id=f"R104-{next_id}")
            stream.write((json.dumps(cmd, separators=(",", ":")) + "\n").encode("ascii"))
            for _ in range(32):
                reply = bounded_read(stream)
                if reply.get("id") != cmd["id"]:
                    # QMP emits unrelated asynchronous hardware events.
                    continue
                if "error" in reply or "return" not in reply:
                    raise RuntimeError("QMP command refused")
                return reply["return"]
            raise RuntimeError("QMP reply ID not received")

        send({"execute": "qmp_capabilities"})
        status = send({"execute": "query-status"})
        if not isinstance(status, dict) or status.get("status") != "running":
            raise RuntimeError("VM is not running")
        for _ in range(KEY_COUNT):
            time.sleep(KEY_INTERVAL_SEC)
            send(key_command())
    print("R104_BOUNDED_QMP_OPTICAL_BOOT_RETURN_ACCEPTED_NOT_WINDOWS_BOOT_PROOF")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owned-root", required=True)
    args = parser.parse_args()
    try:
        qmp = owned_qmp_socket(args.owned_root, os.environ.get("RUNNER_TEMP", ""))
        boot_input(qmp)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        # Avoid exposing filesystem paths, QMP payloads, guest memory or secrets.
        print("R104_QMP_BOOT_INPUT_DENY_CLASS=" + type(exc).__name__)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
