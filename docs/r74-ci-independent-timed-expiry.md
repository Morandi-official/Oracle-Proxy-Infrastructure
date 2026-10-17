# R74 — independently timed native tunnel expiry on disposable Windows CI

R73 proved manual invocation of a separately spawned exact-owned peer stop process after an actual LocalSystem manager crash. R74 adds one narrowly scoped **automatic clock-trigger** test while real native WireGuardNT peers are active; it is not a production watchdog.

## Actual test sequence

On an authorized fresh GitHub-hosted Windows VM, the existing G14 flow compiles pinned real WireGuardNT, starts two genuine native SCM tunnels from authenticated GUI -> LocalSystem manager IPC, checks preactivation config identity/route/DNS scope (R69), independently checks active Windows OS default routes/DNS and exact /32-/128 adapter routes (R70), then verifies real UDP and synthetic A/AAAA DNS delivery with native counters.

The R74-only orchestrator validates the exact running CI manager binary and two running lab peers. While both tunnels still exist, it starts a **separate PowerShell process** with a fixed future expiry approximately 16 seconds away, using a bounded strict UTC timestamp. It then deliberately kills the exact manager process, confirms native peers remain temporarily Running, and **does not explicitly invoke cleanup in the parent**. The separate child waits for the deadline and invokes R73's exact-owned recovery, which refuses unknown service paths, unowned services, missing ephemeral CI markers, stale deadlines, foreign environments and attempts to release before expiry. R73 then stops only the two lab tunnel SCM services and verifies their synthetic peer routes disappear.

The orchestrator waits up to 45 seconds for the watcher process and separately verifies that both native services are Stopped. The original G14 always-run teardown still deletes exact-owned service configurations/binaries/keys and confirms no adapters/routes/SCM peers remain; it compares IPv4/IPv6 default routes, DNS and firewall state with the preflight baseline.

## Limitations

R74 intentionally uses a **nonpersistent child process**, not a Windows Scheduled Task, LocalSystem watchdog service, boot-triggered repair or independent power-failure recovery. Its environment restrictions are CI-only, not production attestation. If that process crashes before the deadline, the OS will not independently recover from this new mechanism. The existing GitHub runner discard is a separate last-resort CI cleanup, not a field-PC solution.

Do NOT run this code on either real Windows computer or Oracle server. No user-side installation or WireSock/UU/Windows network change is permitted by this PR. It does not establish public native Oracle connectivity, WFP full-device leak protection, physical IPv6/DNS packet controls, UU P2P failure survival, signed installer or a safe permanent VPN Off. The shipped production manager continues using `UnavailableProductionKernel`, and GA issue #34 stays open.

Next required R75 before a physical native tunnel trial: a physically recoverable, reviewed independent watchdog that survives manager failure **and** reboot, with exact owned-service lifetime, signed/verified package and operator-confirmed restore; separately approve the temporary Oracle endpoint and Windows host mutation.
