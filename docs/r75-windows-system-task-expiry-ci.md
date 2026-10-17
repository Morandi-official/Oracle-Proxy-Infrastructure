# R75 — hosted Windows SYSTEM Task Scheduler expiry after manager failure

## Why

R74 proved that an already running independent **process** can wait for expiry and stop native WireGuardNT lab peers even if the LocalSystem manager crashes. It did NOT prove Windows owns the scheduled execution. R75 evaluates a one-shot Windows **Task Scheduler** SYSTEM action using a disposable hosted Windows VM. This is not a production installation or field-PC watchdog.

## Experiment

- Use only the existing preflighted GitHub-hosted Windows G14 environment, with fixed CI-owned marker and a transient owned `OracleProxyLab` staging directory. The test already creates two ephemeral WireGuardNT peers, proves authenticated GUI -> LocalSystem SCM start, verifies R69 narrow /32 and /128 peer configs, R70 actual OS route/DNS scope, and exchanges genuine encrypted UDP and tunnel-local DNS A/AAAA.
- The R75 coordinator requires the exact CI manager process path and two live lab peer services. It then registers exactly ONE previously absent Task Scheduler entry, `OracleProxy-R75-CI-Native-Expiry`, running as **LocalSystem**, service-account logon, highest privileges, fixed PowerShell executable and a fixed checked-in worker script, with a short one-time trigger.
- It independently verifies the registered task principal, executable and action arguments **before** terminating the exact owned manager process. It confirms tunnel services remain alive immediately after the manager crash.
- On the scheduled deadline, Windows Task Scheduler (not the dead manager and not a resident GUI-owned watcher) starts the independent SYSTEM worker. It rejects an early/stale expiry, missing run-local ownership marker, missing protected marker, wrong process token, wrong task principal/execute binary, preexisting completion receipt or unknown foreign service path; it then delegates ONLY to R73's already tested exact-owned native test service stop logic.
- The coordinator observes a protected local success receipt, checks both native services are stopped and verifies Task Scheduler reported a zero final exit code. Task registration is never made on a physical host.
- Both the coordinator's `finally` and a separate `always()` CI step independently remove only the validated exact-owned scheduled task. Existing `always()` SCM/native lab cleanup still verifies no experimental adapters, service registrations or synthetic routes remain, then independently checks restoration of default IPv4/IPv6 routes, DNS and firewall.

## Critical limitations

Even a passing R75 tests only one **live-OS one-shot scheduled trigger** on a disposable GitHub Windows runner. It does not prove trigger persistence and successful service cleanup across actual Windows reboot, power loss, Task Scheduler corruption, SYSTEM account changes, unsupported network environments or UU remote-control failure. The new R75 scripts are CI-only and should NOT be transferred or executed on the second Windows PC.

Test-generated private keys and real public Oracle addresses are not accepted, printed or committed. The production manager still uses `UnavailableProductionKernel` and does not gain a connect/Off operation. No user-PC service/driver deployment, OCI VNIC modification, packet capture or production WFP filter is part of R75. The separate real-device VPN test and GA remain blocked by Issue #34.

R71 physical post-test ordinary Internet and UU continuity are now separately **operator-confirmed normal**, and the operator reports being physically present at the second Windows machine. This supports supervised scheduling of later field checks but does not independently attest emergency recovery during a real VPN failure.
