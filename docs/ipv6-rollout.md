# IPv6 rollout and rollback

Oracle GUA `2603:c020:c015:8100::10` is reserved on the existing VNIC. Its subnet
has `2603:c020:c015:8100::/64`, a default IPv6 route through the existing Internet
Gateway, stateful IPv6 egress and ICMPv6 Packet Too Big ingress. This is the same
instance and bandwidth budget; public IPv4 entrances and egress are retained.

The root-owned `oracle-proxy-ipv6-tunnel.service` adds the private WireGuard range
`fd42:6f70:78:77::/64`, NAT66 to the assigned GUA and narrowly scoped forwarding.
Each forwarding accept traverses the existing OPX kernel lease checks first.
Only product-owned peers get an additional stable IPv6 address, derived from
that device's existing IPv4 address. Identity, device slot and traffic history
remain unchanged. Both families share quota, expiry, revocation and server budget.
Unmanaged or administrator-bound legacy peers are not silently migrated.

The service saves forwarding/RA settings and preserves router advertisements
before enabling forwarding. It does not restart networking or change DHCP,
IPv4 addresses/default routes or the secondary IPv4 entrance. Its boot unit
waits for WireGuard and policy control; a failed readiness probe removes public
IPv6 metadata. IPv4 continues to function.

Clients must advertise `dual-stack-v1`. Legacy clients continue receiving only
IPv4 addresses and `ipv6_policy=block`. A new client receives IPv6 only if the
root metadata and its device address are present. The client independently
verifies HTTPS through IPv4 and IPv6 before reporting a connected generation.
Its IPv4 outer carrier can carry IPv6 even on an IPv4-only ISP. IPv6 inner MTU
is 1280; the dual-stack native carrier permits encrypted IPv4 outer datagram
fragmentation on small physical links. IPv4-only native and other carrier
fragmentation policies retain their defaults.

## Apply and rollback

Project operations remain current-main-only. Explicit `enable-https` requests
`ipv6-tunnel-base-apply-20261026` and `ipv6-tunnel-base-rollback-20261026` install or
stop only the owned IPv6 base. Apply requires verified physical IPv6 HTTPS
source and the existing policy chain; rollback removes advertised metadata,
owned NAT/forwarding jumps and the server ULA, restoring saved sysctls. It does
not delete either IPv4 address pair or OCI resources. A stopped IPv6 base makes
new clients return to IPv6-blocked descriptors on refresh.

## Acceptance boundary

Host HTTPS egress alone is not VPN or WebRTC acceptance. Require real Windows
TCP/HTTPS and IPv6 STUN over native UDP, QUIC and HTTPS fallback; low-MTU sustained
traffic; family-6 quota/expiry/revocation; protected/crash leak checks; and real
browser ICE classification. Do not equate absent STUN replies with proof of
privacy, or local ICE disclosure with public route bypass. Do not disable IPv6,
browser WebRTC, certificate checks or the firewall globally to make tests pass.
