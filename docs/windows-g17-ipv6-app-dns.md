# G17: native Windows WireGuardNT IPv6 application and synthetic DNS proof (CI only)

Extension of G14 on a disposable hosted Windows runner. Adds /128 IPv6
addresses fd42:14::1 and fd42:14::2 to the two throwaway WireGuard configs,
plus /128 peer AllowedIPs. IPv4 profiles, 127.0.0.1 UDP transport, keys and
SCM admin IPC remain otherwise scoped as in G14.

The real signed WireGuardNT driver and pinned WireGuard tunnel.dll carry
Windows Winsock IPv6 datagrams in both directions and a synthetic DNS AAAA
query/response over IPv6 UDP/53. The test checks destination socket receipt,
echoed payload, sender IP and genuine driver byte-counter progression.
Temporary test-only Windows Firewall ingress exceptions are each scoped to
exact test executable, test IPv6 addresses and fixed UDP ports, and are
removed in a finally block. No default route, OS DNS resolver, global
firewall policy, WFP, Oracle server, WireSock or UU is touched.

**Limits:** Both tunnel interfaces are on one Windows CI VM and the outer
transport remains localhost IPv4. Driver counter increases correlated with
application delivery do not individually prove every synthetic datagram
was encrypted versus locally delivered. This does not validate Internet
IPv6, DNS resolver leaks, real WFP kill-switch, UU P2P or signing. Do not
consider this a production VPN or remove WireSock based on its success.
