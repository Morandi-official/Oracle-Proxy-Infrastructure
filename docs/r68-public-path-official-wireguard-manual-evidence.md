# R68 — Narrow manual evidence: independent public-network WireGuard path (official client only)

Date: 2026-10-17. Evidence origin: operator-reported console outputs during a physically attended test. This is **not** a GitHub-hosted CI run, an independently captured packet trace, or approval to replace WireSock.

## What was actually tested

- One attended **physical Windows** device used the **official WireGuard Windows client** with a **single /32 inner destination**, no tunnel-provided DNS and no default route through the tunnel.
- A separate existing public Linux host had an **ephemeral, distinct** WireGuard interface with a different UDP port, a temporary keypair, and an isolated /30 inner address space.
- The operator checked the Windows public IPv4 with two independent services before deployment and rechecked before the test. The Windows route selection was via the ordinary Wi-Fi gateway; the WireSock virtual adapter was reported disconnected during the initial route check. This is **not** an external packet capture.
- The cloud-side inbound permission was restricted to that observed public source /32 and temporary UDP port, using a dedicated **VNIC network security group**. The existing subnet security list and production tunnel were not modified.
- On Linux, narrowly scoped tagged INPUT rules admitted the public UDP listener and an inner echo request, then denied other ingress on the temporary interface. Both FORWARD directions involving the temporary interface were explicitly rejected. Existing production forwarding and NAT were left in place.
- A one-shot 30-minute `systemd-run` cleanup timer was confirmed **active** before temporary interface activation, with an explicit scheduled expiry. An operator-tested serial-console login with sudo access and separate SSH sessions were available as recovery paths during the test.
- After the operator enrolled the current Windows public key, the temporary interface was confirmed listening on its separate UDP port, and the official Windows client was activated.
- **Actual Windows ICMP results:** 3 transmitted, 3 received, **0% loss**; 287/289/290 ms round-trip, **288 ms mean**, to the Linux host's temporary *inner tunnel address*. These are the primary cross-host datapath evidence.
- The server's `wg show` excerpt supplied **before** those pings listed the temporary interface/public key/peer/allowed IPs, but did not include a later `latest handshake` timestamp or post-ping transfer counters. Do not claim those fields were captured.

## Cleanup and normal-service evidence

After the test, the operator independently reported:

- The production WireGuard interface was still present and listening on its original port.
- Only the production interface remained in `wg show interfaces`; the temporary test device no longer existed.
- Searching INPUT and FORWARD for the exact R68 marker returned **no residual rules**.
- The extra VNIC NSG was manually **detached**; the production VNIC's NSG association returned to its original empty state.
- Ordinary Windows networking and the UU remote-control program were reported **normal** after the test.

The above validates **observed post-test state**, not whether the cleanup was performed by the timer or a manual command. We lack a post-expiry timer journal, external packet capture, confirmed deletion of the separate NSG *resource*, confirmed deletion of the temporary serial rescue account, and a signed evidence bundle.

## Strict evidence boundaries

**PASS (narrow):** The official WireGuard Windows client reached an independent Internet-facing Linux WireGuard test peer and exchanged ICMP payloads over a single internal address route, with no apparent post-test disruption to the pre-existing VPN/network. The ephemeral Linux interface and tagged firewall rules were observed gone, and the OCI NSG attachment was observed reversed.

**NOT PROVEN:**

1. The repo's **own Windows WireGuardNT client**, release GUI, SYSTEM manager, service identity control and actual production kernel adapter completing any cross-host public tunnel. The shipped manager still uses `UnavailableProductionKernel`.
2. Windows full-device default-route behavior, any all-process IPv4/IPv6 TCP/UDP/DNS leak prevention, independent physical IPv6 traffic or external packet capture.
3. Long-lived UU continuity/reconnection, failover, process identity and WFP bypass policy **during** an active all-device VPN; only normal UU after this *narrow official-client* test was reported.
4. Kill-switch crash/reboot/pre-login recovery, installer signing and rollback, real user-PC safe install, or GA/production readiness.
5. Robust OCI or Linux host isolation: the test shared the production host's kernel. The `systemd-run` timer does not detach an OCI NSG or delete temporary local login accounts.

No public client/server IP, user account name, cloud resource identifier, private key, or network topology detail beyond the minimum test shape is retained here. Do **not** paste original console logs containing real host identifiers into public issues.

## Follow-up

- Keep [GA blocker #34](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues/34) **OPEN**.
- Separately verify no orphan transient cleanup timer, cleanup helper, temporary server test key/config, NSG object or serial rescue user remains; use only exact owned-resource cleanup, after confirming the temporary test interface has already been removed. Do not modify production interface, SSH, firewall defaults, existing NAT or cloud subnet rules.
- For R69, first reproduce the same **single-destination** tunnel from the project's actual authenticated native Windows manager/engine on a **physically recoverable noncritical** Windows system. Do not silently substitute the official WireGuard GUI result. Only after documented independent safety gates should the project consider full-device WFP tests or an installer.
