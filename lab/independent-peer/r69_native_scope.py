"""R69: read-only, CI-only audit of the TWO genuine native WireGuardNT lab profiles.

Not a production policy, public VPN client, profile generator, or authorization
to enable any tunnel. No private-key or endpoint text is ever printed.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import sys

PROFILES = {
    "lab-peer-a": {
        "address": ("10.249.129.1/32", "fd42:14::1/128"),
        "allowed": ("10.249.129.2/32", "fd42:14::2/128"),
        "listen": "52741",
        "endpoint": "127.0.0.1:52742",
    },
    "lab-peer-b": {
        "address": ("10.249.129.2/32", "fd42:14::2/128"),
        "allowed": ("10.249.129.1/32", "fd42:14::1/128"),
        "listen": "52742",
        "endpoint": "127.0.0.1:52741",
    },
}
INTERFACE_FIELDS = frozenset(("PrivateKey", "Address", "ListenPort"))
PEER_FIELDS = frozenset(("PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"))


class AuditError(ValueError):
    pass


def _fail() -> None:
    # Never include untrusted config contents, key material, IPs or paths.
    raise AuditError("Untrusted or overbroad native lab profile")


def _secret64(value: str) -> bytes:
    if len(value) != 44 or not value.endswith("="):
        _fail()
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail()
    if len(key) != 32 or key == bytes(32):
        _fail()
    return key


def _cidr_list(value: str, required: tuple[str, ...]) -> bool:
    # Deliberately no implicit normalization or relaxed prefix parsing:
    # exact fixed addresses, exact families, exact prefix widths and order.
    return tuple(s.strip() for s in value.split(",")) == required


def audit_one(text: str, profile: str) -> tuple[bytes, bytes]:
    """Return ephemeral key bytes for reciprocity only; caller never logs them."""
    if profile not in PROFILES or not 1 <= len(text) <= 2048:
        _fail()
    try:
        text.encode("ascii", "strict")
    except UnicodeError:
        _fail()
    if "\r" in text or "\x00" in text or not text.endswith("\n"):
        _fail()
    group = None
    counts = {"Interface": 0, "Peer": 0}
    values: dict[str, dict[str, str]] = {"Interface": {}, "Peer": {}}
    for original in text.splitlines():
        line = original.strip()
        if not line:
            continue
        if line in ("[Interface]", "[Peer]"):
            group = line[1:-1]
            counts[group] += 1
            if counts[group] != 1:
                _fail()
            continue
        if group is None or "=" not in line or "#" in line or ";" in line:
            _fail()
        k, v = [s.strip() for s in line.split("=", 1)]
        permitted = INTERFACE_FIELDS if group == "Interface" else PEER_FIELDS
        if k not in permitted or k in values[group] or not v:
            _fail()
        values[group][k] = v
    if counts != {"Interface": 1, "Peer": 1}:
        _fail()
    interface, peer = values["Interface"], values["Peer"]
    if set(interface) != INTERFACE_FIELDS or set(peer) != PEER_FIELDS:
        _fail()
    fixed = PROFILES[profile]
    if not _cidr_list(interface["Address"], fixed["address"]):
        _fail()
    if not _cidr_list(peer["AllowedIPs"], fixed["allowed"]):
        _fail()
    if interface["ListenPort"] != fixed["listen"]:
        _fail()
    if peer["Endpoint"] != fixed["endpoint"]:
        _fail()
    if peer["PersistentKeepalive"] != "1":
        _fail()
    return _secret64(interface["PrivateKey"]), _secret64(peer["PublicKey"])


def audit_pair(configs: dict[str, str]) -> None:
    if set(configs) != set(PROFILES):
        _fail()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pairs = {}
    for profile in PROFILES:
        pairs[profile] = audit_one(configs[profile], profile)
    a_private, a_other_public = pairs["lab-peer-a"]
    b_private, b_other_public = pairs["lab-peer-b"]
    a_public = X25519PrivateKey.from_private_bytes(a_private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    b_public = X25519PrivateKey.from_private_bytes(b_private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    if a_other_public != b_public or b_other_public != a_public or a_public == b_public:
        _fail()


def audit_staged_ci_only() -> None:
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.name != "nt"):
        _fail()
    program_data = os.environ.get("ProgramData")
    if not program_data:
        _fail()
    fixed_dir = Path(program_data) / "OracleProxyLab" / "config"
    configs = {}
    for profile in PROFILES:
        path = fixed_dir / (profile + ".conf")
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2048:
            _fail()
        configs[profile] = path.read_text(encoding="ascii")
    audit_pair(configs)


if __name__ == "__main__":
    if sys.argv[1:] != ["--audit-staged"]:
        sys.exit(2)
    try:
        audit_staged_ci_only()
    except (AuditError, OSError, UnicodeError, ValueError, ImportError):
        print("R69_NATIVE_SCOPE_REFUSED")
        sys.exit(3)
    print("R69_NARROW_ROUTES_NO_DEFAULT_DNS_HOOKS_PASS")
