"""Sanitized, read-only WireGuard snapshot collector.

Run separately from the web API under a least-privilege service identity.
Never use 'wg show ... dump': its first record can contain a PRIVATE KEY.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

_INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_COMMANDS = ("listen-port", "latest-handshakes", "transfer", "allowed-ips")


def _wg(interface: str, field: str) -> str:
    result = subprocess.run(
        ["wg", "show", interface, field],
        capture_output=True,
        text=True,
        check=True,
        timeout=8,
    )
    return result.stdout


def _records(value: str) -> list[list[str]]:
    return [line.split("\t") for line in value.splitlines() if line.strip()]


def collect_snapshot(interface: str = "wg0") -> dict:
    if not _INTERFACE.fullmatch(interface):
        raise ValueError("Invalid WireGuard interface name")

    outputs = {field: _wg(interface, field) for field in _COMMANDS}
    peers = {}

    def peer_for(public_key: str) -> dict:
        # Stable, pseudonymous identifier; raw public keys are never serialized.
        identity = hashlib.sha256(public_key.encode("ascii")).hexdigest()[:20]
        return peers.setdefault(identity, {
            "id": identity,
            "allowed_ips": [],
            "latest_handshake": 0,
            "rx_bytes": 0,
            "tx_bytes": 0,
        })

    for fields in _records(outputs["allowed-ips"]):
        if len(fields) != 2:
            raise ValueError("Malformed allowed-ips output")
        peer_for(fields[0])["allowed_ips"] = fields[1].split()

    for fields in _records(outputs["latest-handshakes"]):
        if len(fields) != 2:
            raise ValueError("Malformed latest-handshakes output")
        peer_for(fields[0])["latest_handshake"] = int(fields[1])

    for fields in _records(outputs["transfer"]):
        if len(fields) != 3:
            raise ValueError("Malformed transfer output")
        item = peer_for(fields[0])
        item["rx_bytes"] = int(fields[1])
        item["tx_bytes"] = int(fields[2])

    return {
        "interface": interface,
        "listen_port": int(outputs["listen-port"].strip()),
        "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "peers": sorted(peers.values(), key=lambda item: item["id"]),
    }


def write_snapshot(snapshot: dict, target: Path) -> None:
    # Create files in an already provisioned directory, never expose world-readable status.
    if not target.parent.is_dir():
        raise ValueError("Output directory must already exist")
    fd, temporary = tempfile.mkstemp(prefix=".wg-snapshot-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(snapshot, output, ensure_ascii=False, separators=(",", ":"))
            output.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect public WireGuard status only")
    parser.add_argument("--interface", default="wg0")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    write_snapshot(collect_snapshot(args.interface), args.output)


if __name__ == "__main__":
    main()
