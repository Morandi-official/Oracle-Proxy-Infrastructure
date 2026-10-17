# R62 — Remote-control continuity is a **separate fail-closed admission gate** (model only)

## Problem and scope

R59 proved that a *separate Edge profile* could reach Gmail through a
localhost OpenSSH SOCKS5 proxy and disconnect without observed UU disruption.
It did **not** test an all-device WireGuard route, WFP block, long-lived P2P
sessions, UDP signaling/relay, IPv6, service reboot or Wi-Fi failover.
R48–R50 tested only narrowly scoped disposable Windows CI destinations.
These successes cannot authorize switching the user's only remote-control
channel to a VPN, or using a guessed UU executable name, vendor IP/range,
static exception or a blanket WFP permit.

## R62 implementation (no OS mutation)

`RemoteControlContinuityEvidence` models ten individually necessary pieces
of evidence, **all currently unavailable** in the production adapter:
independent OS session inventory, signed image/path and OS token identity,
complete remote endpoint and transport inventory, IPv4/IPv6 TCP+UDP direct
continuity, DNS/dynamic reclassification policy, no unknown remote flows,
VPN-underlay isolation, real out-of-band recovery, and witnessed reconnect
continuity after a controlled failure.

`ProductionVpnCoordinator` rejects *before* unsealing a WireGuard key or
starting a tunnel if this evidence is missing. It rechecks after authenticated
tunnel proof, during explicit Off and immediately before WFP release. Missing
or stale evidence latches `RecoveryRequired`; it never automatically permits
WFP release. Offline `FakeKernel` negative tests vary every boolean, fail
after handshake and fail between durable Off intent and WFP release.

**Importantly** the actual SYSTEM service still constructs
`UnavailableProductionKernel`, which returns default/false and cannot
start the tunnel, create a UU exception, alter DNS, set WFP or release policy.
All CI tests are purely synthetic; *no* process name, packet trace, signing
identity, IP, phone number or remote-control credential is collected.

## Before implementation can leave negative-only mode

- Identify remote-control processes through independent installed-signature,
  verified full path and active OS tokens, not matching strings alone.
- Demonstrate on a separable, physically recoverable Windows test machine
  which TCP, UDP, DNS and IPv4/IPv6 paths UU truly needs, including changes
  after reconnect, adapter switch, sleep, reboot and loss of tunnel.
- Classify P2P and relay traffic; a static whitelist or socket snapshot is
  insufficient. Unclassifiable endpoints must **stop the proposal**, not
  silently permit all traffic.
- Prove the exact WFP physical-interface policy preserves remote control
  while denying unintended packets, with independent captures across a real
  second network peer and actual UU remote reconnection.
- Verify physical-console authority and out-of-band restoration **before**
  activating anything that could strand a remote operator. No blanket
  auto-undo commands or silent system proxy/WFP changes on user computers.
- Verify system-owned filter lifetime, boot/crash semantics, dedicated
  owned-policy release and transparent operator confirmation.
- Require signed installer, protected WireGuard driver/key bundle and separate
  final GA approval; keep Issue #34 open until real evidence exists.

This is a security gate, **not an implemented UU compatibility feature** and
not evidence of full-device leak protection.
