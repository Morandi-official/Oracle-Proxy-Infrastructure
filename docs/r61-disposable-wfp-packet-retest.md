# R61 — Current-main disposable Windows fixed-destination WFP packet retest

**2026-10-17**, PR #91 / Windows run
https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993067517

This test reuses the previously reviewed R31/R46 **four fixed public
resolver-address** firewall experiment and its exact ownership and
cleanup checks. It is limited to a disposable GitHub-hosted Windows runner,
never the user's Oracle server, WireSock/UU computer, or production VPN.
Its temporary firewall policy applies to those exact four external
destination addresses, all processes/protocols, not the entire Internet.

## Observed job logs and what they prove

- `R31_UNAUTHORIZED_OPERATION_REFUSED_PASS` — negative guard rejects
  non-disposable invocation without leaving a rule.
- `R46_UNBLOCKED_IPV4_TCP_DNS_BASELINE_PASS` — real external IPv4 TCP
  port 443 and raw UDP DNS probes reached a fixed approved endpoint before
  installation; testing does **not** rely exclusively on rule metadata.
- `R46_OS_WFP_IPV4_TCP_UDP_DNS_DENIED_PASS` — new sockets/requests at the
  chosen same IPv4 endpoints could not complete while CI-owned OS policy
  blocked the fixed destination set.
- `R46_IPV6_PACKET_PROOF_UNAVAILABLE: no IPv6 baseline, not a pass` —
  **IPv6 packet denial was not established** by this run. Scope of a
  dual-stack rule in the OS inventory is not proof of real IPv6 denial.
- `R31_OS_ALL_APPLICATION_IPV4_IPV6_WFP_RULE_ACTIVE_PASS` — narrowly
  scoped real policy metadata covered both address families; not packet-level
  all-device egress evidence.
- `R46_OS_WFP_REAL_TCP_DNS_RESTORE_PASS` — reachable IPv4 TCP/UDP DNS
  endpoints became reachable again after removal.
- `R31_OWNED_WFP_RELEASE_AND_OS_BASELINE_PASS` — exact owned rule removed,
  OS default route and firewall profile baselines preserved. Final cleanup
  step also succeeded.

Default-branch source/release guard succeeded on PR #91.

## Still release-blocking

No Internet-wide TCP+UDP+DNS IPv4/IPv6 fail-close or live full-tunnel
leak prevention was proven. No pre-login/boot/third-party-rule collision,
native signed installer, interface switching, independent external
capture, UU P2P/relay bypass or remote recovery was tested here. A
GitHub-hosted Windows runner's network availability can vary.
There is **no** evidence that changing a user PC's WFP/default route
is safe. Keep `UnavailableProductionKernel` and issue #34.

Never convert this narrowly scoped CI test into an unrestricted
physical-interface WFP block on a remotely accessed Windows computer.
