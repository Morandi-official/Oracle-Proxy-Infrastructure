# R50 — Explicit, SYSTEM-owned WFP release after a confirmed lab Off

R49 proved a fixed all-application WFP rule persists across an abrupt
manager crash and an unsafe restart is refused. R50 tests a *different*
transition: after successful synthetic LocalSystem WireGuardNT handshake
and stopped manager/native peers, a separate demand-only LocalSystem
release service may delete ONLY the precisely audited CI-owned,
four-public-target WFP rule.

The release service is excluded from the default manager build. It has
no GUI/IPC entrypoint and no variable destinations or caller-provided
profile. It checks its own real SYSTEM Session-0 token, fixed protected
ProgramData ownership marker, an existing PASS native handshake receipt,
one newly staged explicit-release approval marker, no pending release
receipt, the primary manager in Stopped state, no fixed ephemeral lab
adapters or native child process, and full matching
`CiSystemFixedTargetWfpGuard` metadata before any mutation.

Disposable Windows CI attempts the release service *without* the marker
and must observe startup refusal and actual TCP/UDP DNS still blocked.
Only after the primary service and peers are stopped does the workflow
create the fixed authorization marker and retry. The release-only SYSTEM
process removes the exact verified WFP rule, proves no same-name rule
remains, and writes a single-use PASS receipt. A separate PowerShell
process independently checks absence of the rule and restored TCP 443/
raw UDP DNS. It then deletes only those two CI SCM registrations and
temporary test stage, and verifies routes/DNS/Firewall baselines.

Limits: The marker is **CI test authorization**, NOT a secure production
identity or user consent protocol; it is locally writable by Windows
administrators in the ephemeral runner. Receipt integrity is not
cryptographically tied to real tunnel packets. The policy protects only
four fixed public destinations, not all IP traffic or UU. No durable
route/DNS recovery transaction, power-loss proof, native full-device WFP
provider, signed Windows installer, Oracle modification or production
connection is part of R50. GA issue #34 stays open and
`UnavailableProductionKernel` remains the production adapter.
