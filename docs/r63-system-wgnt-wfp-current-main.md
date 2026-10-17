# R63 — Revalidated R48 SYSTEM/DPAPI/WireGuardNT and narrowly scoped WFP

2026-10-17, disposable Windows GitHub runner:
https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993399003

PR #93 re-enables the historically restricted R48 Windows SCM integration
workload **only** for this exact temporary branch. It uses ephemeral keys and
fresh runner resources, pinned signed upstream WireGuardNT DLL, a disposable
LocalSystem manager, and four immutable public resolver target addresses.
The default distributable manager still contains
`UnavailableProductionKernel` and has no CI command entry point.

Observed run log markers:

- `R44_DPAPI_SEALED_KEYS_PASS`: generated ephemeral keys sealed before disk.
- `R48_PRE_FILTER_REAL_TCP_DNS_BASELINE_PASS`: baseline before WFP policy.
- `R48_EXACT_SINGLE_IP_COM_SERIALIZATION_AND_NEGATIVE_SCOPE_PASS`: narrow
  fixed address validation; no broad prefix allowed.
- `R48_SYSTEM_ALL_PROCESS_IPV4_TCP_UDP_DNS_PACKET_DENIAL_PASS`: OS backed
  LocalSystem-created, all-application rule blocked real IPv4 TCP443 and UDP DNS
  at selected fixed endpoints during native handshake.
- `R47_REAL_SYSTEM_NATIVE_DPAPI_WIREGUARDNT_HANDSHAKE_PASS`: synthetic
  **localhost** two-peer encrypted native WireGuardNT handshake via memory
  secret, not actual public Internet tunnel.
- `R48_OWNED_WFP_REMOVED_AND_TCP_DNS_RESTORED_PASS`: exact owned rule
  removed and independently reachable probes restored.
- `R47_SYSTEM_SCM_STAGE_CLEANUP_PASS`: temporary service/staging removed.
- `R48_IPV6_EXTERNAL_BASELINE_UNAVAILABLE_NOT_PROVEN`: **no external IPv6
  packet denial proof** in this runner.

Both R48 workflow and default-branch non-VPN source/release safety workflow
completed successfully. This CI evidence advances real SYSTEM native integration,
but does **not** implement a production GUI -> SYSTEM -> WireGuard tunnel switch.
The actual service still refuses privileged connections. It proves no all-device
network fail-close, no complete IPv4/IPv6/UDP/DNS coverage, no reboot/first
logon, no independent Internet WireGuard peer, no UU P2P continuity, and
no safe release from user PCs.

Never interpret fixed-target WFP tests as permission to modify the production
Oracle instance, Windows default route, firewall, WireSock or UU. GA #34 remains
open and unsigned driver/installer may not ship as VPN replacements.
