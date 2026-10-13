# G13 — actual kernel WireGuard over Linux isolated multihop lab

Status: **experimental cloud-runner network evidence**, not a Windows/Oracle
VPN release and NOT cross-host Internet verification.

GitHub Actions creates three temporary Linux **network namespaces on one
hosted Ubuntu VM**: A (client), M (routed middle), B (server).
The veth underlay is A -> M -> B. Separate kernel wg0 interfaces on A and
B establish an actual WireGuard handshake with newly generated throwaway
keys and exchange encrypted IPv4/IPv6 packets through M. A tiny fixed,
nonrecursive DNS responder on B answers A and AAAA wire-format queries over
inner UDP/53. A tcpdump capture on M checks outer WireGuard UDP packets
exist and rejects visible plaintext synthetic tunnel addresses/port 53.
It also interrupts/restores M's veth path and verifies the narrow inner
routes remain pointed at wg0 while the tunnel is down.

## Isolation/safety

- Runs with an explicit opt-in on a disposable **GitHub-hosted Linux** VM;
  creates only namespace-local IP addresses, routes, and links, then cleans
  them up on exit. It never runs on a user's Windows PC or Oracle instance.
- **No** network calls to Oracle, UU, WireSock or a third-party DNS service;
  no production keys, config, credentials or artifacts. All keys and captures
  are local to a root-owned temporary directory deleted by the EXIT trap.
- No changes to the VM's default network namespace routes, resolver, nftables
  or iptables. The only forwarding setting changes are inside namespace M.
- Uses reserved test IP ranges 198.18.0.0/15, 10.200.250.0/24,
  fd42:13::/64, 203.0.113.0/24, 2001:db8::/32 inside the isolated lab.

## Evidence and strict limitations

Successful G13 proves real Linux kernel WireGuard UDP encapsulation through a
three-namespace routed topology, tunneled IPv4/IPv6 **inner** traffic,
synthetic DNS A/AAAA messages, and this particular controlled outage
recovery. A middle-namespace pcap is stronger evidence than an app Boolean,
but still only observes this emulated lab's traffic.

**It does NOT prove** connection between separate physical machines/public
IPs; Windows WireGuardNT interoperability; Windows full-tunnel DNS behavior;
Windows WFP packet blocking, IPv4/IPv6/DNS fail-closed on a physical interface;
UU direct P2P preservation; or Oracle production readiness. In particular,
only the synthetic /32 and /128 routes are controlled: ordinary physical
default-route traffic is not blocked. A successful test must not be
represented as a kill switch.

The stronger pending G9/G10 acceptance still needs an *independent* accessible
peer and Windows lab with demonstrated external console/snapshot rollback.
Don't install WFP filters or stop UU on the critical remote computer.
