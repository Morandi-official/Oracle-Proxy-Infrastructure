# R46 — actual Windows WFP fixed-destination socket denial (CI only)

Build on R31's **all-process, all-protocol, IPv4+IPv6** Windows OS
Firewall/WFP-backed filter that targets only two fixed public IPv4 and
two fixed public IPv6 test resolver addresses. The test:

- Refuses non-elevated or non-disposable hosted Windows execution.
- Observes repeatably successful IPv4 TCP/443 and raw DNS UDP/53 from
  freshly opened sockets to the fixed test destinations **before** adding
  a filter; otherwise it fails with baseline-unavailable, not a pass.
- Creates exactly the R31-owned single fixed-destination WFP rule.
- Requires new IPv4 TCP and UDP DNS requests to fail while that rule
  is active. If independently reachable IPv6 TCP/443 exists, it too
  must be blocked; lack of public IPv6 reachability prints
  `R46_IPV6_PACKET_PROOF_UNAVAILABLE`, **not** an IPv6 pass.
- Removes only the verified owned filter and checks that both original
  IPv4 protocol tests (and IPv6 when present) succeed again, along
  with unchanged default routes and Windows Firewall profile settings.
- Runs a negative unauthorized-operation test and an independent
  cleanup check on the disposable CI VM.

The observations are actual Winsock TCP/UDP sends/receives, not just
WFP object metadata. They are **not external packet captures** and
only cover these fixed destinations and tested protocol combinations.
Nothing installs a default-deny whole-device kill switch, tests UU,
proves DNS from every interface or attests pre-login/crash persistence.
No Oracle, WireSock or user host is touched; issue #34 remains blocking.
