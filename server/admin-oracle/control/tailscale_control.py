"""Headscale admission via the control plane's local administrative socket."""

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from tailscale_egress import POOLS

_AUTH_KEY = re.compile(r"hskey-auth-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}")
_USER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def _positive_id(value):
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("INVALID_HEADSCALE_ID")
    return value


@dataclass(frozen=True)
class Admission:
    user_id: int
    ticket_id: int
    credential: str = field(repr=False)


@dataclass(frozen=True)
class BoundNode:
    node_id: int
    addresses: tuple[str, str]


class HeadscaleControl:
    ticket_lifetime_seconds = 300

    def __init__(self, binary, configuration):
        self.binary = Path(binary)
        self.configuration = Path(configuration)
        if not self.binary.is_absolute() or not self.configuration.is_absolute():
            raise ValueError("LOCAL_HEADSCALE_PATHS_REQUIRED")

    def _call(self, *arguments):
        try:
            result = subprocess.run(
                [self.binary, "--config", self.configuration, *arguments, "--output", "json"],
                env={"LANG": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                check=True,
                timeout=8,
                capture_output=True,
            )
            return json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            # Headscale errors can include enrollment URLs. Callers log this
            # generic error only. The API key environment is not inherited.
            raise OSError("HEADSCALE_CONTROL_UNAVAILABLE") from None

    def issue(self, user_id):
        user_id = _positive_id(user_id)
        value = self._call(
            "preauthkeys", "create", "--user", str(user_id), "--expiration", f"{self.ticket_lifetime_seconds}s",
            "--reusable=false", "--ephemeral=false",
        )
        key = value.get("key")
        if not isinstance(key, str) or not _AUTH_KEY.fullmatch(key):
            raise OSError("INVALID_HEADSCALE_CREDENTIAL")
        return Admission(user_id, _positive_id(value.get("id")), key)

    def find_node(self, username, user_id, ticket_id):
        if not isinstance(username, str) or not _USER_NAME.fullmatch(username):
            raise ValueError("INVALID_HEADSCALE_USERNAME")
        user_id = _positive_id(user_id)
        ticket_id = _positive_id(ticket_id)
        nodes = self._call("nodes", "list", "--user", username)
        if nodes is None:
            return None  # Headscale serializes an empty Go slice as null.
        if not isinstance(nodes, list):
            raise OSError("INVALID_HEADSCALE_NODE_LIST")
        matches = [
            node for node in nodes
            if (node.get("pre_auth_key") or {}).get("id") == ticket_id
            and (node.get("user") or {}).get("id") == user_id
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise OSError("AMBIGUOUS_HEADSCALE_REGISTRATION")
        node = matches[0]
        addresses = {}
        for value in node.get("ip_addresses", []):
            address = ipaddress.ip_address(value)
            if (address.version in addresses or address not in POOLS[address.version]
                    or getattr(address, "scope_id", None) is not None):
                raise OSError("INVALID_HEADSCALE_NODE_ADDRESS")
            addresses[address.version] = str(address)
        if addresses.keys() != {4, 6}:
            raise OSError("DUAL_STACK_HEADSCALE_NODE_REQUIRED")
        return BoundNode(_positive_id(node.get("id")), (addresses[4], addresses[6]))

    def revoke(self, node):
        self._call("nodes", "delete", "--identifier", str(_positive_id(node.node_id)), "--force")

    def expire_ticket(self, ticket_id):
        self._call("preauthkeys", "expire", "--id", str(_positive_id(ticket_id)))
