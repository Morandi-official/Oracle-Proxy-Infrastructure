# R84 — SYSTEM Task Scheduler safe-stops a RUNNING non-network SCM field mock

R82 proved that an OS-owned SYSTEM scheduled task can expire only **OFFLINE** field lease/config files. R83 correctly blocks real field WireGuardNT activation even with valid metadata, because a local consent boolean and file-only cleanup are not safe authorization or a live service Off. R84 narrows the next risk using a real **running Windows SCM service** that deliberately has zero networking functionality.

## Test scope — single disposable hosted Windows runner

- A separately compiled .NET Windows `ServiceBase` process has exact SCM service name `WireGuardTunnel$lab-field` but contains **no WireGuard driver, no sockets, no VPN, no route/DNS/firewall/WFP mutations and no secrets**. It is a STOPPABLE status-only mock, never a native test VPN. Before SCM startup it verifies SYSTEM/Session0 and an isolated owned fixture marker.
- Create a protected synthetic R81 one-peer `10.77.72.2/32` candidate and short lease, but no public packets are sent. Stage the mock binary as an Administrators/SYSTEM-only file and register the exact owned SCM mock in Manual mode. Assert the SCM binary path and LocalSystem identity.
- **Register and verify** a one-shot Task Scheduler entry `OracleProxy-R84-CI-MockSafeStop` as SYSTEM ServiceAccount/Highest, with an exact script and future expiry **before the mock enters Running**. A non-SYSTEM or premature call to its worker must be denied with the mock service untouched.
- In a separate CI step, without sending any stop command, wait for Windows Task Scheduler to run the SYSTEM worker. The worker checks due UTC time, task principal and command, exact owned marker and file ACLs, exact service binary path/identity and currently Running state, then stops **only** `WireGuardTunnel$lab-field` and removes only the two owned synthetic config/lease files.
- Independent always-run cleanup removes the exact owned scheduled task, verifies SCM service binary identity before service deletion, deletes the owned mock binary, then invokes R81's exact stage cleanup. Compare real Windows IPv4/IPv6 default routes, DNS and firewall inventory with the preflight baseline and assert no residual service, task or file.

## Critical nonclaims

R84 is **NOT a live WireGuardNT safe-Off proof**: the service is a no-network mock, so it cannot demonstrate driver unload, adapter teardown, WFP protection during unexpected failure or recovery across reboot/power loss. R75 previously stopped genuine native WireGuardNT lab peers after manager death on a single GitHub Windows runner, but it did not operate on a physical Windows computer. Neither is a substitute for full production and UU continuity acceptance.

R83's real native field load gate remains **blocked**, the normal production build excludes this field mode, and GA Issue #34 remains open. Before touching the user's second Windows PC or actual Oracle ephemeral UDP listener/NSG, separate user authorizations are required. This CI test does not grant or request those permissions.
