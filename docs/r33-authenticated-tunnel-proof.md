# R33: authenticated tunnel data proof, not production activation

## Field evidence (operator-reported, 2026-10-16)

A physical Windows official WireGuard diagnostic tunnel and an existing
remote Linux WireGuard peer exchanged application UDP echo payloads over a
temporary, scoped Internet UDP forwarding path. Windows sent 44 messages and
matched 42 echo replies; server recorded 44 received and 44 replies, with
WireGuard peer byte-counter deltas (RX 4,404 / TX 4,464).
The 2 missing echoes were **not** attributed to packet loss, and no long-run
availability estimate is justified. Remote cloud ingress and Linux rules
were verified back to baseline. This was **not** traffic through the
repository's own Windows VPN service.

No public IP addresses, configuration secrets or user-specific topology are
included in source control.

## Integration in this patch

The production coordinator's success path now demands an
`AuthenticatedTunnelProof` object, rather than a Boolean
`VerifyEncryptedTunnelAndRoutes` response. Its offline predicate requires:

- actual native service and pinned/verified fixed peer;
- fresh authenticated handshake in the same tunnel session;
- application challenge socket bound to the owned tunnel, unpredictable
  single-use challenge response checked, and owned routes verified;
- DNS guarded by independently verified OS-owned WFP coverage;
- strictly increasing **both** encrypted RX and TX counters (same pinned peer);
- at least one matched application response, no count greater than sent.

The existing production adapter remains `UnavailableProductionKernel`.
This patch **does not construct or approve** a real evidence producer,
does not start a tunnel, does not configure WFP, does not load keys or
alter Oracle, and must not be treated as production functional Alpha.

## Required future system implementation

Evidence must be freshly collected **inside trusted SYSTEM service code**
after starting a fixed, signed tunnel and auditing actual OS WFP. It must
never be accepted from IPC/GUI/config file/CI outputs. To prevent
false positives, implement challenge binding to the exact adapter/interface,
independently measured encrypted counters for the fixed peer, a
cryptographically unpredictable session challenge, and an actual in-tunnel
reply check with timeout, robust replay protection, abort and fail-closed
rollback. A remote echo endpoint is not an identity oracle without peer
authentication. The source/destination UDP port may be configured only in
a separately signed fixed service profile, never by GUI JSON. An application
echo also cannot establish physical-interface IPv4/IPv6/DNS fail-close.

All production release security gates in issue #34 remain blocked.
