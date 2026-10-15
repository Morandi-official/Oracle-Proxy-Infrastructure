# R25 — restart of actual LocalSystem SCM manager with existing CI WFP policy

R21 proved that a Windows Firewall/WFP persistent policy installed by the
SYSTEM service survives a hard manager crash. Previously, however, an
unchanged rule with the fixed test name caused manager restart to be
rejected. That was fail-safe but prevented recovery after crashes.

R25 changes the **compile-time-enabled disposable CI manager only**:
after confirming real SYSTEM/Session0 identity, fixed protected lab marker,
fixed executable and exact existing Windows Firewall COM policy name, startup
must accept an already present policy ONLY when all previously audited
security dimensions remain unchanged (action, protocol, direction, enabled,
program path, complete local/remote address scope and all profiles). It
does NOT reinstall, replace, silently widen or delete an existing rule.
A modified rule still fails startup.

Cloud Windows integration on synthetic two-peer WireGuardNT services:
1. Manager creates an OS-backed, persistent narrow program-specific WFP rule
   before exposing its authenticated admin pipe.
2. GUI starts two real native fixed test peer services; actual handshake,
   encrypted application UDP and synthetic DNS data are verified.
3. Script hard-terminates only the exact CI-owned LocalSystem manager PID and
   proves the peers and physical TCP/UDP DNS WFP policy survive.
4. Windows SCM starts the same signed-by-scope lab manager registration anew;
   identity and changed process PID are checked. No duplicate firewall rule
   may appear, while real external TCP/UDP DNS remain blocked.
5. GUI authenticated stop/start of a synthetic peer must re-establish a
   WireGuard handshake while the original WFP guard persists. GUI explicitly
   stops both peers; the exact CI rule is explicitly released afterwards.
6. Final cleanup confirms no residual service, key, route, DNS, adapter or
   firewall policy remains. Failures do not authorize a production VPN.

Boundaries: no actual reboot, no whole-device IPv4/IPv6 DNS kill switch,
no WireSock/UU coexistence, no production VPN or installer. WFP adoption is
only of the strictly fixed process-scoped lab rule, and same-name policy
provenance cannot withstand a compromised administrator. Production trust
requires signed installer/service, service SID/ACLs, independently verified
fail-close packet capture and rescue. #34 remains blocked.
