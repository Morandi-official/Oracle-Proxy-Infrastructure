"""R77: CI-only protected external single-peer profile staging (NO VPN).

Generates one ephemeral synthetic test X25519 private key and writes exactly
one CI-owned native candidate config under a presecured directory. No real
Oracle address, keys, probe, service startup, installer or uploaded artifact.
"""
import base64
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

import r76_single_public_profile as render


def main(argv: list[str]) -> int:
    if argv != ["--stage-owned-ci"]:
        return 2
    if (os.name != "nt" or os.environ.get("RUNNER_OS") != "Windows" or
            os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("ORACLE_R77") != "CI_ONLY" or
            not os.environ.get("ProgramData")):
        print("R77_REFUSED")
        return 3
    root = Path(os.environ["ProgramData"]) / "OracleProxyR77Only"
    marker = root / ".r77-owned"
    target = root / "lab-peer-a.conf"
    try:
        if root.is_symlink() or target.exists() or marker.is_symlink() or \
                not marker.is_file() or marker.read_text(encoding="ascii").strip() != \
                "CI_R77_ONLY_DISPOSABLE_GITHUB_VM":
            raise ValueError("Unowned directory")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        client = X25519PrivateKey.generate()
        client_private = client.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        client_public = client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        synthetic_server = X25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        server_public = synthetic_server.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        proposal = {
            "schema_version": 1,
            "mode": "review_only_single_public_peer",
            "created_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_utc": (now + timedelta(minutes=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "client_inner_ipv4": "10.77.72.2/32",
            "server_inner_ipv4": "10.77.72.1/32",
            "allowed_ips": ["10.77.72.1/32"],
            # Both test addresses are syntactically global; NO packets sent.
            "server_endpoint_ipv4": "8.8.8.8",
            "observed_client_public_ipv4": "9.9.9.9",
            "server_udp_port": 51828,
            "client_public_key": base64.b64encode(client_public).decode("ascii"),
            "server_public_key": base64.b64encode(server_public).decode("ascii"),
            "duration_minutes": 10,
            "dns_policy": "preserve",
            "default_route_policy": "preserve",
            "ipv6_policy": "do_not_configure",
            "firewall_policy": "no_system_firewall_mutation",
            "driver_policy": "no_install_or_replace",
            "separate_operator_approval_required": True,
        }
        plan_bytes = json.dumps(proposal, separators=(",", ":")).encode("utf-8")
        conf = render.render_in_memory(plan_bytes, client_private, now=now)
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(conf)
            stream.flush()
            os.fsync(stream.fileno())
        if target.is_symlink() or target.stat().st_size > 512:
            raise ValueError("Bad candidate output")
        # Read-back comparison, never print or upload the secret-bearing data.
        if target.read_text(encoding="ascii") != conf:
            raise ValueError("File verification differs")
        print("R77_ONE_EXCLUSIVE_PROTECTED_CANDIDATE_STAGED_NO_NETWORK_PASS")
        return 0
    except (OSError, ValueError, UnicodeError, TypeError):
        print("R77_REFUSED")
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
