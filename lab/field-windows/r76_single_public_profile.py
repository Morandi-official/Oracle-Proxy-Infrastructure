"""R76: pure in-memory, single-inner-/32 WireGuardNT lab profile rendering.

NO file I/O, host mutation, tunnel startup, CLI provisioner, encryption key
vault or authorization is implemented here. Intentionally NOT production.
"""
from __future__ import annotations

import base64
import hmac
import json
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import r72_narrow_plan as scope


class ProfileRefused(ValueError):
    pass


def refuse() -> None:
    # Do not include any proposal content or secret bytes in exceptions.
    raise ProfileRefused("R76_NARROW_PROFILE_REFUSED")


def render_in_memory(proposal: bytes, client_private: bytes,
                     *, now: datetime | None = None) -> str:
    """Review-only candidate. Secret-bearing return value MUST NEVER be logged."""
    if type(client_private) is not bytes or len(client_private) != 32 or \
            client_private == bytes(32):
        refuse()
    try:
        _ = scope.validate(proposal, now=now)
        plan: dict[str, Any] = json.loads(proposal.decode("utf-8"))
        private = X25519PrivateKey.from_private_bytes(client_private)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        planned_public = base64.b64decode(plan["client_public_key"], validate=True)
        if not hmac.compare_digest(public, planned_public):
            refuse()
        # The validated R72 proposal is *not* authority to connect. It only
        # limits exactly which text can be constructed for later review.
        conf = (
            "[Interface]\n"
            "PrivateKey = " + base64.b64encode(client_private).decode("ascii") + "\n"
            "Address = " + scope.CLIENT_INNER + "\n"
            "\n[Peer]\n"
            "PublicKey = " + plan["server_public_key"] + "\n"
            "AllowedIPs = " + scope.SERVER_INNER + "\n"
            "Endpoint = " + plan["server_endpoint_ipv4"] + ":" +
                str(plan["server_udp_port"]) + "\n"
            "PersistentKeepalive = 25\n"
        )
        # An additional independent, exact grammar/size audit is applied to
        # the output before any future staging code can consume it.
        if not exact_profile_grammar(conf, plan):
            refuse()
        return conf
    except (scope.PlanRejected, ValueError, TypeError, KeyError, UnicodeError):
        refuse()


def exact_profile_grammar(config: str, proposal: dict[str, Any]) -> bool:
    if not isinstance(config, str) or len(config) > 512:
        return False
    if "\r" in config or "\x00" in config or not config.endswith("\n"):
        return False
    lines = config.splitlines()
    if len(lines) != 9 or lines[0] != "[Interface]" or lines[3] != "" or \
            lines[4] != "[Peer]":
        return False
    if not lines[1].startswith("PrivateKey = "):
        return False
    if lines[2] != "Address = " + scope.CLIENT_INNER or \
            lines[5] != "PublicKey = " + proposal["server_public_key"] or \
            lines[6] != "AllowedIPs = " + scope.SERVER_INNER or \
            lines[7] != ("Endpoint = " + proposal["server_endpoint_ipv4"] + ":" +
                         str(proposal["server_udp_port"])) or \
            lines[8] != "PersistentKeepalive = 25":
        return False
    return True


def authorizes_service_or_connection(_: object = None) -> bool:
    return False


if __name__ == "__main__":
    # No file paths, no output profiles, no keys via CLI.
    raise SystemExit(2)
