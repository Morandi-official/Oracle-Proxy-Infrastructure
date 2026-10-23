"""Narrow, isolated WireGuard lab configuration generator (NO networking).

Server private key stays on the independently owned lab Linux VM.
Client private key stays on the isolated Windows lab VM.
Only public keys cross machines through a trusted provisioning channel.
No output or config may ever reference the existing Oracle production server.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import os
from pathlib import Path

SERVER_ADDR = "10.249.134.1/32"
CLIENT_ADDR = "10.249.134.2/32"
LAB_PORT = 52901
PRODUCTION_ORACLE = ipaddress.ip_address("152.67.156.100")


def key(value: str) -> str:
    text = value.strip()
    raw = base64.b64decode(text, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("Expected one canonical 32-byte WireGuard key")
    return text


def private_key_file(path: str) -> str:
    requested = Path(path)
    if requested.is_symlink():
        raise ValueError("Symlink private-key input prohibited")
    filename = requested.resolve(strict=True)
    if not filename.is_file():
        raise ValueError("No ordinary private key file")
    if os.name != "nt" and filename.stat().st_mode & 0o077:
        raise ValueError("Lab private key file must be owner-only")
    return key(filename.read_text(encoding="ascii"))


def endpoint(value: str) -> str:
    host = ipaddress.ip_address(value)
    if not isinstance(host, ipaddress.IPv4Address):
        raise ValueError("This narrow lab profile supports IPv4 endpoint only")
    if not host.is_global or host == PRODUCTION_ORACLE:
        raise ValueError("Endpoint must be a separately owned public lab IPv4 address")
    return str(host)


def config(mode: str, private: str, remote_pub: str,
           public_endpoint: str | None = None) -> str:
    private = key(private)
    remote_pub = key(remote_pub)
    if mode == "server":
        return (
            "[Interface]\n"
            f"Address = {SERVER_ADDR}\n"
            f"ListenPort = {LAB_PORT}\n"
            f"PrivateKey = {private}\n"
            "\n[Peer]\n"
            f"PublicKey = {remote_pub}\n"
            f"AllowedIPs = {CLIENT_ADDR}\n"
        )
    if mode == "client":
        if not public_endpoint:
            raise ValueError("Independent lab server IPv4 is required")
        public_endpoint = endpoint(public_endpoint)
        return (
            "[Interface]\n"
            f"Address = {CLIENT_ADDR}\n"
            f"PrivateKey = {private}\n"
            "\n[Peer]\n"
            f"PublicKey = {remote_pub}\n"
            f"AllowedIPs = {SERVER_ADDR}\n"
            f"Endpoint = {public_endpoint}:{LAB_PORT}\n"
            "PersistentKeepalive = 20\n"
        )
    raise ValueError("Unknown lab profile")


def safe_write(destination: str, text: str) -> None:
    path = Path(destination)
    if path.parent.is_symlink():
        raise ValueError("Symlink output directory prohibited")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Unsafe lab output directory")
    if path.exists() or path.is_symlink() or path.suffix.lower() != ".conf":
        raise ValueError("Refuse to overwrite or redirect lab config")
    # Atomic exclusive new owner-only file; never print contents.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    if os.name != "nt":
        path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["server", "client"])
    parser.add_argument("--local-private-key-file", required=True)
    parser.add_argument("--remote-public-key", required=True)
    parser.add_argument("--lab-endpoint-ipv4")
    parser.add_argument("--output")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--lab-confirm", default="")
    args = parser.parse_args()

    own = private_key_file(args.local_private_key_file)
    conf = config(args.role, own, args.remote_public_key,
                  args.lab_endpoint_ipv4)
    if args.dry_run:
        print("LAB_DRY_RUN_OK: " + args.role +
              " /32-only peer; no default route, DNS, Oracle or OS changes")
        return
    if args.lab_confirm != "INDEPENDENT_VM_WITH_CONSOLE_AND_SNAPSHOT":
        raise ValueError("Independent VM and out-of-band recovery not confirmed")
    if not args.output:
        raise ValueError("Explicit new lab config output path required")
    safe_write(args.output, conf)
    print("LAB_CONFIG_STAGED: protected new config only; no tunnel started")


if __name__ == "__main__":
    main()
