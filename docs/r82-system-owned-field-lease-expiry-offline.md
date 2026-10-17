# R82 — Windows SYSTEM Task Scheduler autonomously expires a field-lease fixture (OFFLINE ONLY)

R81 already proved default compiled service-host cannot accept lab-field and that an explicit diagnostic build can offline-validate an expiring protected one-peer /32 candidate without starting a native service. R82 adds an **OS-owned expiration trigger** before any future real field trial; it still has NO VPN activation path.

## Experiment on one disposable GitHub-hosted Windows runner

1. Snapshot real Windows default IPv4/IPv6 routes, DNS server configuration and firewall rule count. Confirm no pre-existing `OracleProxyLab` root.
2. Stage one synthetic R81 field lease + config under strict Admin/SYSTEM-only protected NTFS ACLs. Endpoint `8.8.8.8:51828` remains an uncontacted fixture, and hardcoded fixture key bytes are not real user keys.
3. Register the one-shot OS-owned `OracleProxy-R82-CI-Field-Offline-Expiry` task as SYSTEM/Highest/ServiceAccount with an exact fixed PowerShell worker and a 43-second future expiration. Recheck task identity and reject an early or non-SYSTEM invocation, while preserving both files.
4. Finish the registration step immediately, and run a SEPARATE later workflow step which merely waits and checks Task Scheduler execution history, eventual successful exit, and that the protected config and lease were removed. The observing process NEVER invokes the worker or manipulates the schedule.
5. The SYSTEM worker independently validates its own identity, scheduled task principal/action, exact owned marker, protected root/config/marker/config/lease ACLs, and the timestamp due within three minutes. It refuses any native lab-field service already present, then deletes only the two named synthetic files. It cannot start or stop WireGuardNT, touch Oracle, change routes/DNS/firewall or manage UU.
6. Independent `always()` steps unregister only that exact owned task, remove the remainder of the synthetic R81 stage, compare the before/after OS network fingerprints, and assert no service, temporary root or scheduled task survives.

## What success cannot claim

This is an **offline synthetic configuration expiration** and one live Windows OS scheduler trigger, not a working VPN watchdog. It deliberately refuses to stop an active native service, has no reboot/power-loss test and cannot guarantee restart restoration or crash-safe post-reboot key erasure. An observed timer firing in cloud CI is not proof that a physical UU/WireSock device remains reachable during actual VPN driver failure. R81 lease `operator_confirmation_recorded` boolean is NOT cryptographic or independently witnessed consent. Do not deploy this workflow's task, keys or diagnostic build to the user's second Windows computer.

The public native WireGuardNT-to-Oracle handshake, signed and separately approved packaging, independent reboot-persistent safe-off mechanism, packet-level WFP IPv4/IPv6/DNS leakage proof and UU failure continuity remain mandatory unsatisfied field/GA gates. Default `UnavailableProductionKernel` and Issue #34 remain blocked. Separately request permission before touching real Oracle NSG/firewall/wgtest interface or any physical Windows native service/driver.
