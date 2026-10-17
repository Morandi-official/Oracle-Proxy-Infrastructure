# R65 — Current-main authenticated GUI IPC / SCM native WireGuardNT lab

Date: 2026-10-17. PR #95, one-off GitHub Windows runner:
https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993730675

The previously branch-gated G14 workflow was re-run against current main.
It compiled pinned genuine upstream tunnel DLL, Windows native service
host, the CI-only admin-capable manager and GUI, then generated two
ephemeral lab WireGuard X25519 keypairs and staged fixed ACL-protected
narrow-route profiles on a disposable Windows runner.

Actual job log markers:

- `PASS: official signed x64 WireGuardNT DLL and pinned C compiler authenticated`
- `PASS: official tunnel DLL, service host, admin manager, native GUI and observer compiled`
- `G14_PASS: two-way real Winsock UDP app socket delivery + inner synthetic DNS A/AAAA; genuine WireGuardNT Tx/Rx counters advanced. Localhost-only, not cross-host or no-leak proof.`
- `G17_PASS: actual IPv6 Winsock two-way sockets plus DNS AAAA UDP/53 over IPv6 narrow lab peers; native counters advanced. NOT Internet IPv6/WFP no-leak or UU proof.`
- `G14_FW_CLEANUP: exact temporary per-program test firewall rules removed`
- `R6_TUNNEL_ROLLBACK_PASS: no synthetic IPv4/IPv6 routes, adapters or SCM peer services remain`
- `R6_OS_RESTORE_PASS: IPv4/IPv6 default routes, DNS servers and Windows Firewall rules restored`

This is a useful **test-only** GUI to Windows OS-authorized manager IPC to
SCM/tunnel data path, but cannot be plugged into the distributed GUI's
production buttons. The production LocalSystem manager still installs
`UnavailableProductionKernel`. The test peers share one Windows VM, not
independent Internet hosts. The IPv6 DNS success was inside a lab tunnel;
it is **not** a physical external IPv6 WFP kill-switch test. There was
no dynamic UU relay/P2P failover, native signed installer, or production
Oracle test. Keep GA Issue #34 open.
