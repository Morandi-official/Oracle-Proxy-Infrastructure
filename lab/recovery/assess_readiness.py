"""Lab acceptance GATE, not packet enforcement or proof by itself.

Explicitly requires operator-observed evidence obtained OUTSIDE the VPN VM,
from independently controlled console, snapshots and network captures.
True values passed as input remain untrusted until separately reviewed.
"""
from __future__ import annotations
import json
from pathlib import Path

CHECKS = (
    "isolated_vm_no_oracle_or_uu_production",
    "out_of_band_console_verified",
    "snapshot_restore_performed_without_guest_network",
    "automatic_wfp_rollback_tested",
    "service_crash_and_forced_reboot_recovered",
    "ipv4_tcp_udp_no_physical_egress_when_vpn_enabled",
    "ipv6_tcp_udp_no_physical_egress_when_vpn_enabled",
    "dns_ipv4_ipv6_no_physical_egress_when_vpn_enabled",
    "unknown_process_no_egress_when_vpn_down",
    "verified_uu_udp_p2p_remains_direct_when_vpn_down",
    "authorized_user_off_restores_normal_direct",
    "cold_boot_fails_closed_before_user_sign_in",
)


def readiness(evidence: dict) -> tuple[bool, tuple[str, ...]]:
    if not isinstance(evidence, dict):
        return False, CHECKS
    missing = tuple(name for name in CHECKS if evidence.get(name) is not True)
    # Identity, origin, signed capture files and firewall behaviors are not
    # established by mere JSON. Always include a human technical audit gate.
    return not missing, missing


def report(path: str) -> str:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    ok, missing = readiness(obj)
    if missing:
        return "BLOCKED_UNVERIFIED: " + ", ".join(missing)
    return "DOCUMENT_CHECKLIST_COMPLETE_NOT_SECURITY_ATTESTED"


if __name__ == "__main__":
    import sys
    print(report(sys.argv[1]))
