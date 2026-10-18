# R92 — independent real-Windows-reboot evidence gate (deny-only)

## Scope and regression safety

R89 proved **manually triggered** SYSTEM AtStartup Task Scheduler action stopped genuine local WireGuardNT CI tunnel services, with zero owned-file/SCM/route/adapter/key remnants and restored IPv4/IPv6/DNS/firewall. It did **not reboot Windows**. R92 adds a Windows-compiled **read-only evidence adjudicator** and a built-in negative test matrix; no privileged service entrypoint or release controls are added.

The new C# `R92RebootRecoveryGate` compares independently observed pre/post boot-identity records for the *same noncritical machine* and requires positive claims for out-of-band console/snapshot rollback, pre-login IPv4/IPv6 TCP/UDP/DNS packet WFP captures, verified native safe stop, fixed SYSTEM signer/identity, exact owned restoration, UU continuity, third-party WireSock/UU configuration preservation, tested network isolation/key revocation, and external witness attestation.

**Important trust boundary:** The inputs are still only **claims**. Different claimed boot IDs, timestamps, or even all-true booleans are **never cryptographic attestation or a greenlight for action**. Every verdict denies: automatic connect, WFP release, route/DNS mutation, physical field approval, installer publication. A syntactically complete comparison returns `R92_EXTERNAL_ATTESTATION_AND_HUMAN_REVIEW_REQUIRED_DENY`, not approval. OS evidence must be independently inspected by a separately controlled system before any production decision.

On GitHub-hosted Windows, the test runs the manager as an unprivileged read-only CLI, compares actual Windows `Win32_OperatingSystem.LastBootUpTime` around two separate process invocations, and asserts the boot time **did not change**. This deliberately proves a process restart **is not** a real OS reboot. No attempt to call Restart-Computer, force power loss, register a real startup service, modify WFP/Firewall, inspect UU packet contents or change network is made.

## Prerequisites for a meaningful first real reboot experiment

- A **noncritical disposable Windows VM** managed by an independent controller, with a **demonstrated working console, disk snapshot, rollback and remote power-control**. The test controller and rollback procedure must not share the OS access path which the WFP experiment will intentionally impair. Do not repurpose a UU-dependent remote computer, Oracle's active wg0 instance or a production Windows endpoint.
- Separately authenticated, externally captured VM identity and boot IDs, timestamps and boot transition. An in-guest PowerShell message, task scheduler result, registry flag or JSON `rebooted=true` is insufficient.
- A controlled isolated peer/network, no production credentials; strict TTL, key revocation and route firewall isolation proven first.
- Obtain the correct real Windows Authenticode publisher identity, signed exact-owned installer and rollback payload, and ensure existing Windows execution/App Control policies allow it; **do not bypass policy**. R91 Github Sigstore build attestation **does not** substitute for Authenticode.
- A restore operator, independent UU session monitor, packet-capture observer on all IPv4/IPv6 interfaces including DNS, explicit abort and rollback conditions (missing console/boot attestation, unexpected route, UU loss, non-owned filter, post-boot leak, incomplete cleanup).

## Required trial sequence (not executed by R92)

1. Capture signed-independent before-state: external machine+boot identity, Windows build, test VM snapshot/restore proof, actual interfaces/default routes, IPv4/IPv6/DNS, WFP provider+filter ownership, SCM service paths/SIDs/start types, UU continuity. Preserve out-of-band console and emergency snapshot.
2. Only in the authorized disposable environment, install precisely scoped **signed, reviewed** trial components, and establish persistent boot-appropriate SYSTEM-owned WFP recovery before any native tunnel start. Independently inspect persistent filter state and reversible emergency access. Do not claim that current R83 field client can do this: it cannot.
3. Arm time-bounded nonproduction tests. Cause controlled service crash and collect real OS/WFP packet deny evidence, with independent UU session monitoring.
4. Use the independent console to perform a **real** Windows reboot (not `Start-ScheduledTask`), observe the new OS boot ID and pre-login blocked leakage at an independent network tap, then verify any SYSTEM recovery process, exact signer/SCM identity and **fail-closed** state.
5. Run an explicit authorized safe Off and exact-owned uninstall using already reviewed recovery procedures; compare external packet/network baseline, SCM/route/DNS/WFP state and file inventory. Revoke ephemeral credentials, and verify independent console/snapshot rollback still works.
6. Package signed/hash-pinned outside-host evidence for independent review; record every failure as a hard block, never convert a single green CI into production release approval.

## Current limitations and remaining release blockers

No independent snapshot-recoverable Windows VM with actual OS reboot was operated here. The current GitHub-hosted runner has no independently demonstrated restore console to support a dangerous boot/WFP test. No signed Windows installer or reviewed publisher identity is available; no new OCI instance, Oracle wg0/NSG changes, third-party WireSock/UU changes, user Windows WFP/DNS/route modifications, code signing procurement or physical R86 execution have been performed.

Production `UnavailableProductionKernel` remains hard-denied and R83 field native activation refuses even valid leases. GA Issue #34 remains OPEN. **R92 is a tested evidence-contract hard stop, not reboot success or release authorization.**
