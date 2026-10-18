# R89 — real CI WireGuardNT safe-stop through a manually fired SYSTEM AtStartup task

**Strict evidence label:** `R89_ATSTARTUP_SYSTEM_NATIVE_STOP_MANUALLY_TRIGGERED_PASS_NO_REBOOT` is **NOT** a test of actual Windows reboot, pre-login network behavior, power failure, unattended restart, persistent WFP, or recovery on any user computer.

## Scope and relation to prior work

R75 already demonstrated genuine Windows SYSTEM Task Scheduler deadline stopping *running* native WireGuardNT peers in a disposable GitHub Windows runner after the CI manager crashed. R89 deliberately **reuses the exact R73 identity-checked owned native stop** in a second startup-phase scheduling arrangement, without editing the production manager, NativeDriverTrust, WireGuardNT bundle pins, production WFP, field activation or Oracle.

A branch-restricted existing G14 disposable Windows CI job validates real signed WireGuardNT 1.1 and pinned official tunnel toolchain, builds two ephemeral/native localhost-linked peers, proves real encrypted UDP and synthetic DNS via GUI→OS authenticated IPC→LocalSystem manager→SCM, then:

1. Verifies the exact CI-owned staging markers, live manager process path and **both Running native peer services**.
2. Registers an exact uniquely named **AtStartup** Task Scheduler action as LocalSystem/Highest, verifies its trigger, action and principal before inducing a manager crash. The script refuses any pre-existing task/receipt and refuses physical/non-GitHub-runner execution.
3. Shows the peers remain Running after the manager process is killed. **Without rebooting**, the CI coordinator issues `Start-ScheduledTask` on the *already registered* AtStartup task. This tests SYSTEM launch, not a boot trigger actually firing.
4. The new SYSTEM worker checks Session 0/SYSTEM, exact task identity and CI markers, then calls the already reviewed R73 exact-owned native stop. The coordinator verifies the two SCM services are Stopped, synthetic peer IPv4/IPv6 routes disappear, Task Scheduler recorded a **recent run timestamp** and exit 0 (without a separate SYSTEM-owned receipt file).
5. Both local `finally` and a separate GitHub `always()` cleanup verify/delete **only the exact R89 owned task**, while the independent G14 cleanup removes native SCM services, ephemeral keys, owned stage and all adapters and verifies default routes/DNS/firewall baseline. **R89 now requires a positive zero-residual result for the entire owned staging directory, manager SCM registration, per-job marker and ephemeral key file**; an earlier green R89 CI run emitted a warning that the temporary staging directory could not be deleted promptly, so its success was insufficient to claim exact file cleanup. The strict R89 cleanup retries for a bounded period, then fails the CI rather than relying on eventual runner destruction.

## What is still missing

The GitHub-hosted Windows runner is **not restarted**: the test manually starts the AtStartup job. It cannot establish that the task survives and fires during a true OS reboot, that stopped Manual services would be running after reboot, or that WFP actually remains fail-closed before user login. A persistent boot/recovery design requires a disposable VM with independent console/rollback and real reboot evidence; the physical second PC and Oracle remain outside this authorization.

Do not expand these tests to boot-start production WireGuard services or all-device WFP. No field driver is installed on a user machine; no system network changes outside the ephemeral GitHub runner. R83 runtime native field denial, compiled `UnavailableProductionKernel`, signing and GA Issue #34 remain blocked. Even a green R89 CI is not a tested live user safe-Off or a signed Windows installer.

## R89 cleanup fault reproduced and corrected at source

The initial green native stop run logged delayed directory deletion. A strict follow-up CI then **failed** with Windows `UnauthorizedAccessException` (`0x80070005`, `RemoveFileSystemItemUnAuthorizedAccess`) when attempting to remove the protected staged directory. This is distinct from route, adapter or SCM cleanup. The original SYSTEM worker wrote a new receipt file with SYSTEM-specific default ownership/DACL in the non-inheriting native stage. Instead of relaxing ACLs or accepting incomplete cleanup, the CI coordinator now relies on **recent Task Scheduler LastRunTime + LastTaskResult=0**, exact owned SCM status and actual OS synthetic route absence as independent proof of SYSTEM execution. It no longer creates the problematic SYSTEM receipt. Strict zero-owned-file cleanup remains mandatory and must pass fresh CI before merge. A successful CI without actual OS reboot still cannot satisfy the separate real reboot requirement.
