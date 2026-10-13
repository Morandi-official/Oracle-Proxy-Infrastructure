# G14 — real Windows application UDP delivery and synthetic DNS over narrow lab profiles

This adds a disposable-GitHub-Windows-only Winsock probe to the existing G12
GUI → authenticated privileged IPC → LocalSystem manager → two temporary
WireGuard SCM peers lab.

It binds real UDP application sockets to both tunnel addresses, sends fixed
1200-byte payloads each direction, and checks recvfrom() receives exact
bytes and the expected IP/port. It additionally exchanges valid minimal
DNS UDP/53 A and AAAA query/response packets for a static lab.invalid
name over the same tunnel IP pair. It then checks that actual signed
WireGuardNT peer counters advanced. It changes no Windows system DNS,
routes, firewall, WFP rules, drivers, Oracle or UU. All peers and secret
keys are ephemeral within a Windows GitHub runner and deleted afterward.

**Important limitations:** both interfaces are assigned on one Windows
machine: local OS delivery is possible and counter correlation alone does
NOT cryptographically prove these particular application datagrams were
encapsulated rather than locally routed. G14 also does not test IPv6,
default-route redirection, external server UDP, Windows DNS resolver
integration, WFP fail-closed, UU live P2P or a signed release.

Any test failure leaves the PR draft and the project NOT RELEASE-READY.
