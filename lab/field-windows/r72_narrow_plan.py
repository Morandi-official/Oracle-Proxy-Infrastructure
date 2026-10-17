"""R72: independently review ONE future attended public WireGuard trial proposal.

This tool ONLY validates an untrusted metadata proposal. It does not generate
WireGuard configs, manage keys, install drivers, authorize a connection or
touch any network settings. Approval and physical recovery MUST be separate.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys


FIELDS = frozenset({
    "schema_version", "mode", "created_utc", "expires_utc",
    "client_inner_ipv4", "server_inner_ipv4", "allowed_ips",
    "server_endpoint_ipv4", "server_udp_port", "observed_client_public_ipv4",
    "client_public_key", "server_public_key", "duration_minutes",
    "dns_policy", "default_route_policy", "ipv6_policy",
    "firewall_policy", "driver_policy", "separate_operator_approval_required",
})

# These constants identify only a future proposal's PRIVATE tunnel scope.
# No server identity, real endpoint or credential is shipped in source.
CLIENT_INNER = "10.77.72.2/32"
SERVER_INNER = "10.77.72.1/32"
MAX_MINUTES = 20


class PlanRejected(ValueError):
    pass


def _deny() -> None:
    # Do not echo untrusted input, keys, public endpoints or file paths.
    raise PlanRejected("R72_INVALID_OR_UNAPPROVED_SCOPE")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            _deny()
        data[key] = value
    return data


def _public_key(value: object) -> bytes:
    if not isinstance(value, str) or len(value) != 44:
        _deny()
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _deny()
    if len(raw) != 32 or raw == bytes(32):
        _deny()
    if base64.b64encode(raw).decode("ascii") != value:
        _deny()
    return raw


def _global_unicast(value: object) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        _deny()
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        _deny()
    if (str(address) != value or not address.is_global or address.is_multicast
            or address.is_reserved or address.is_loopback or
            address.is_link_local or address.is_unspecified):
        _deny()
    return address


def _utc_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _deny()
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _deny()
    return dt.replace(tzinfo=timezone.utc)


def validate(raw: bytes, *, now: datetime | None = None) -> str:
    """Return a harmless digest used to identify the proposal, NOT consent."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 4096:
        _deny()
    try:
        text = raw.decode("utf-8", "strict")
        plan = json.loads(text, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: _deny())
    except (UnicodeError, ValueError, TypeError):
        _deny()
    if not isinstance(plan, dict) or set(plan) != FIELDS:
        _deny()
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        _deny()
    if plan["mode"] != "review_only_single_public_peer":
        _deny()
    if plan["client_inner_ipv4"] != CLIENT_INNER or \
       plan["server_inner_ipv4"] != SERVER_INNER or \
       plan["allowed_ips"] != [SERVER_INNER]:
        _deny()
    if type(plan["server_udp_port"]) is not int or \
       plan["server_udp_port"] != 51828:
        _deny()
    if (type(plan["duration_minutes"]) is not int or
            not 5 <= plan["duration_minutes"] <= MAX_MINUTES):
        _deny()
    if (plan["dns_policy"] != "preserve" or
            plan["default_route_policy"] != "preserve" or
            plan["ipv6_policy"] != "do_not_configure" or
            plan["firewall_policy"] != "no_system_firewall_mutation" or
            plan["driver_policy"] != "no_install_or_replace"):
        _deny()
    if plan["separate_operator_approval_required"] is not True:
        _deny()
    endpoint = _global_unicast(plan["server_endpoint_ipv4"])
    client = _global_unicast(plan["observed_client_public_ipv4"])
    if endpoint == client:
        _deny()
    if _public_key(plan["server_public_key"]) == \
       _public_key(plan["client_public_key"]):
        _deny()
    created = _utc_time(plan["created_utc"])
    expires = _utc_time(plan["expires_utc"])
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        _deny()
    now = now.astimezone(timezone.utc)
    if not (created <= now <= expires and
            now - created <= timedelta(minutes=5) and
            timedelta(minutes=1) <= expires - created <=
            timedelta(minutes=plan["duration_minutes"])):
        _deny()
    # Digest is for integrity comparison only; no approval/token issued.
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def authorizes_any_connection(_: object = None) -> bool:
    # Deliberately no production/CI environment flag or opt-in bypass.
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--review-proposal":
        return 2
    try:
        path = Path(argv[1])
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
            _deny()
        digest = validate(path.read_bytes())
        if authorizes_any_connection(digest):
            _deny()
        print("R72_REVIEW_ONLY_VALID_SHA256=" + digest)
        print("R72_CONNECT_AUTHORIZED=false")
        return 0
    except (OSError, PlanRejected, UnicodeError, ValueError):
        print("R72_SCOPE_REFUSED")
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
