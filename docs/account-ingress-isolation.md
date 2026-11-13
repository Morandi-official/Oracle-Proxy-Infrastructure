# Per-account primary / backup ingress

New and existing users default to **primary only**. In Users & Quota, administrators
can select primary only, backup only, or both. The preferred entry must belong to
the allowed set. For both, the other entry is the UDP fallback. Editing these
settings does not allocate a new device, reset quota, or change billing anchors.

## Enforcement

The primary entry keeps its existing WireGuard identity. The backup entry has an
independent root-owned key and the `wgopbackup` kernel interface. Only authorized
user keys are installed on each interface. Native UDP 443, 8443 and 51820 on the
backup private address are redirected to its internal port 51821. That port is not
a public alternative: only the exact DNAT original destination/port or loopback
relays are accepted. QUIC and HTTPS relays target the WireGuard interface matching
the actual receiving address; the HTTP ingress header is overwritten by Caddy.

Kernel leases, revocation, account expiry and the server budget cover both
interfaces. Per-interface counters are reconciled separately before aggregating
per device and account. Upload/download policers are shared between interfaces
and between IPv4/IPv6; opening both entries does not double the account rate.
Raw IPv6 listeners and former IPv4 aliases cannot bypass the two configured IPv4 entrance selectors. IPv6 payloads remain fully supported inside the tunnel. Only marked inner return traffic uses table 196. Physical default routes and OCI
public/private mappings remain unchanged.

The fixed boot helper prepares the backup route and its interface-specific loose
reverse-path setting. The sandboxed policy service cannot change global sysctls.
It refuses backup grants until the helper's root-owned readiness identity matches.
Server private keys stay in the root-only control state directory and are never sent to RPC,
HTTP, exported profiles, logs, or artifacts. Only public server keys are advertised.

## FlClash

The existing profile UUID, URL token and client key remain stable. New profile
responses contain both fixed WireGuard nodes in a UDP-only fallback group. A
server permission change makes an unauthorized node fail even if a user edits the
file or manually selects it. A pre-provisioned profile can switch to the remaining
authorized node without restarting Mihomo or changing the file.

Use the original remote subscription and enable its automatic update in FlClash.
The response supplies a one-hour update hint; the application controls whether it
honors that hint. Preferred ordering changes are read on subscription refresh.
There is no push channel into an offline YAML file. A historical local file with
only one node needs a **one-time** update or import of its existing subscription
URL to obtain the two-node format; subsequent permission changes do not require
new files or device registration.

## Windows client

rc41 selects the server public key corresponding to each allowed ingress, including
UDP diagnostics. Single-entry users have three allowed UDP diagnostic targets;
dual-entry users have six. Existing rc40 clients keep primary connectivity, but
should upgrade before using automatic fallback across the independently keyed
entries. Permission removal is enforced on the server regardless of client version.

## Rollout / verification

After activation, application rollback to relay versions without ingress isolation is refused; use an ingress-aware release to preserve server enforcement.

Do not deploy the draft until the real isolated WireGuard, forwarding, dual-stack,
manual-edit denial, shared policer, unchanged-Mihomo-profile and Windows acceptance
checks pass. Check the production primary connection, then an explicitly granted
backup test device. Keep both existing reserved public IP mappings and DNS intact.
Do not change unrelated users to dual-entry access for testing.

## IPv4 exit follows ingress

Each new primary flow is SNATed to the primary private IPv4; each backup flow is SNATed to the backup private IPv4. OCI maps those source addresses to their respective reserved public IPv4 addresses. The private addresses must exist on the configured VNIC before rules are applied. Only the application-owned tunnel-source NAT chain is replaced; host default routes, account identities, shared quota/rate enforcement and the common IPv6 exit remain unchanged. Primary packets clear only the reserved backup mark bit. Existing NAT connections may retain their original mapping until reconnected; deployment does not flush unrelated conntrack entries.

Forwarded backup IPv4 flows use conntrack original-direction zone 196 and reply-direction zone zero. The two translated private destination addresses distinguish replies, while identical inner five-tuples remain independent. Local gateway services and encrypted outer UDP/QUIC/HTTPS keep ordinary conntrack handling. IPv6 keeps the existing common egress policy.
