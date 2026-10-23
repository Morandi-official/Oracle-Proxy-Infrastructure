# R41 — Failed WFP release: compensation contract (NOT production actuation)

## Risk addressed

R35 added a second OS WFP audit before an explicit Off. However, the abstract
`ReleaseOnlyOwnedWfp` call could return false or throw **after partially
releasing** some owned filters. Likewise, direct-network restoration could
fail after the release completed. A simple `RecoveryRequired` state prevents
further GUI operations but cannot restore already weakened OS policy.

R41 adds `TryReestablishOwnedWfpGuard()` to the production-kernel
**interface**, and makes the transaction try it when WFP release was
attempted and the operation did not finish safely. It never calls this
method on a pre-release failure. It never treats a successful compensation
attempt as proof of leak-free transport or a completed Off; the state stays
`RecoveryRequired` and requires out-of-band verification.

The default installed `UnavailableProductionKernel` still returns false
without any mutation. The current implementation does NOT install native WFP
filters, restore physical connections, or recover from a process crash.
An actual adapter will require durable ownership data, OS-layer atomicity/
audits and signed all-device IPv4/IPv6/DNS enforcement; no code here
authorizes release or connects WireGuard.

## CI

R4 executes the coordinator on the Windows runner with a fake kernel.
Negative tests cover pre-release failures (no compensating calls), partial
release and post-release verification failures (compensation attempted),
compensation exceptions (state remains latched), and successful explicit
Off (no compensation). These are contract tests, **not packet captures**.

Issue #34 remains the GA blocker. Keep the production connection gate closed
and preserve Oracle, WireSock, UU and user machine networking.
