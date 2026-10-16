# R34 disposable nonce echo: evidence boundary

This change adds **executable Windows native integration testing**, not an
implementation of `IProductionVpnKernel` or a production acceptance claim.

The G11 Windows hosted lab runs two already-staged official WireGuardNT
SCM peers with local, ephemeral keys and /32 routes. The R34 probe:

1. Opens only the synthetic `lab-peer-a` and `lab-peer-b` interfaces.
2. Reads each single-peer WireGuardNT LastHandshake and encrypted byte counters.
3. Creates a 256-bit challenge using Windows BCryptGenRandom, binds Winsock
   sockets to the fixed narrow-route IPv4 addresses and validates the exact
   echo payload, responder address and UDP port.
4. Rejects deliberately corrupted and stale-equivalent nonce replies.
5. Re-reads both driver counters and requires positive Tx **and** Rx deltas.
6. Refuses non-GitHub-hosted CI invocations. The runner also exercises this
   denial before successful testing.

**Limitations:** The two peers are on the same CI VM. An IP-bound socket is
not a cryptographic proof of owning a physical tunnel interface, nor is this
an independent packet capture. The same-host traffic and counter increments
do not establish which individual packet increased the counters. The test
process is not a LocalSystem production evidence collector. It does not pin
a production peer public key, prove route ownership from OS state, audit
all-device physical IPv4/IPv6/DNS WFP, prove crash/boot atomicity or test UU.
The negative stale-equivalent echo is synthetic, not a long-lived replay
attack against a production service. No external host or real user credentials
are involved.

The actual Windows service remains wired to `UnavailableProductionKernel`;
no production connect or disconnect is enabled.

## CI acceptance

The R34 allowlisted G11 job must **run, not skip**, and complete its
original upstream source verification, SYSTEM SCM activation, signed driver
preflight, independent cleanup and unchanged default-route assertions.
Look for `R34_NATIVE_NONCE_ECHO_PASS` and
`R34_CI_NATIVE_RANDOM_CHALLENGE_VERIFIED` in the executed job's log.
A queued, skipped, cancelled or failing run is **not** an accepted result.

Future work: move a session-bound challenge into a trusted SYSTEM collector
with a separately authenticated peer and pinned public key, validated
interface identity and routes, and independent OS/WFP validation. Maintain
issue #34 as the production GA blocker.
