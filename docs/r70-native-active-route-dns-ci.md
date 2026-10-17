# R70 — Validate active native WireGuardNT OS routes and DNS (CI-only)

## Why this matters

R68 proved a narrow route to a separate public host only with the official Windows WireGuard GUI. R69 then independently audited the test profiles *before* actual native WireGuardNT SCM activation on a disposable runner. R70 closes a different test gap: the **live OS state while the actual native tunnel is active** must stay narrow, not merely restore routes after cleanup.

## Live Windows CI audit

The G14 hosted Windows test uses its independent pre-tunnel snapshots and calls `clients/windows/lab/Test-R70NativeLiveRouteScope.ps1` only after both fixed lab peer services are started through authenticated GUI -> LocalSystem manager control, and before sending real UDP + synthetic DNS packets.

- Refuses execution without exact hosted CI environment, protected owned-lab marker and a prior snapshot.
- Reads (does not alter) real Windows default IPv4/IPv6 routes; requires exact baseline equality during the active tunnel.
- Requires two distinct named native adapters, each exposing the exact synthetic peer /32 IPv4 and /128 IPv6 route, and forbids default or widened /24 and /64 adapter prefixes.
- Rejects actual or unknown DNS server addresses attached to native lab adapters. Some Windows native adapters report precisely three legacy IPv6 site-local placeholder addresses (fec0:0:0:ffff::1/::2/::3) despite no DNS profile entry; only these exact sentinel values can be classified as OS placeholders, with positive and negative classification tests and only a safe count logged. Separately requires existing interfaces' DNS server configuration to remain equal to the pre-activation baseline. This is **not** a DNS packet leak test.
- Runs a negative unhosted invocation and then real WireGuardNT duplex UDP and DNS packet tests. Always-run cleanup independently rechecks services, interfaces, routes, DNS and firewall count.

**No network change is initiated by the new audit.** The existing tunnel services only run on disposable GitHub Windows CI, with dedicated lab keys and fixed localhost peer endpoints. Success marker: `R70_ACTIVE_NATIVE_ROUTES_AND_DNS_NARROW_PASS`.

## Limitations

This demonstrates that active synthetic lab *routing and DNS configuration* remain narrow. It is **not** an all-device WFP packet leak test, not proof of physical Internet IPv6 protection, not dynamic UU session continuity, and not native client-to-Oracle public path acceptance. The default Windows distribution continues to use `UnavailableProductionKernel` and refuses production connect/Off. GA blocker [#34](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues/34) remains open.
