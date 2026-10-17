# R64 — Current-main disposable SYSTEM WFP crash quarantine and safe-Off

Date: 2026-10-17. PR #94 revalidated previously CI-branch-locked R49
and R50 experiments on **two separately disposable Windows runners**.
All observations below are limited to four hard-coded public resolver
addresses, never a full-device kill switch or user PC.

## Crash / restart — R49

Run: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993527564

Observed logs:
- `R48_PRE_FILTER_REAL_TCP_DNS_BASELINE_PASS`
- `R48_SYSTEM_ALL_PROCESS_IPV4_TCP_UDP_DNS_PACKET_DENIAL_PASS`
- `R47_REAL_SYSTEM_NATIVE_DPAPI_WIREGUARDNT_HANDSHAKE_PASS` (two
  localhost peers only, ephemeral sealed keys)
- `R49_SYSTEM_MANAGER_CRASH_WFP_RULE_PERSISTS_AND_BLOCKS_PASS`: after
  force-ending exactly the owned LocalSystem manager, a narrowly scoped
  OS WFP rule still blocked new fixed-target IPv4 TCP/UDP DNS.
- `R49_UNVERIFIED_RESTART_DENIED_WITH_WFP_PERSISTENCE_PASS`: unsafe restart
  refused and OS policy remained active.
- `R48_OWNED_WFP_REMOVED_AND_TCP_DNS_RESTORED_PASS` and
  `R47_SYSTEM_SCM_STAGE_CLEANUP_PASS`: bounded CI recovery/cleanup.
- `R48_IPV6_EXTERNAL_BASELINE_UNAVAILABLE_NOT_PROVEN`.

## Explicit safe Off — R50

Run: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993527579

Observed logs:
- `R50_DEFAULT_BINARY_EXCLUDES_RELEASE_AND_NON_SYSTEM_REFUSED_PASS`:
  CI-only ownership/release service entrypoint absent from normal manager.
- `R50_SYSTEM_RELEASE_WITHOUT_EXPLICIT_APPROVAL_REFUSED_PASS`:
  native WFP fixed-target OS block remained until test approval.
- `R50_EXPLICIT_SYSTEM_OWNED_WFP_RELEASE_PASS`: exact CI-created
  fixed-target OS filter released only by the separate SYSTEM service
  after fixed service/peer preconditions and CI approval marker.
- `R48_OWNED_WFP_REMOVED_AND_TCP_DNS_RESTORED_PASS` and
  `R47_SYSTEM_SCM_STAGE_CLEANUP_PASS`: restored previously reachable
  IPv4 TCP+UDP DNS targets, removed only ephemeral stage.
- `R48_IPV6_EXTERNAL_BASELINE_UNAVAILABLE_NOT_PROVEN`.

Both jobs and the PR's source/release safety workflow completed SUCCESS.

**Do not generalize this result.** Temporary CI release marker is NOT
actual end-user consent, atomic off/rollback, or a cryptographically bound
evidence receipt. No real public WireGuard peer, IPv6 packet proof, unknown
interface change, DNS system redirection, reboot/power cut, dynamic UU
remote P2P/relay endpoint inventory, OOB physical rescue, signed installer
or production Oracle was exercised. A 35-second driver isolate does not
establish UU compatibility. Keep normal `UnavailableProductionKernel`
in place and keep GA Issue #34 open.
