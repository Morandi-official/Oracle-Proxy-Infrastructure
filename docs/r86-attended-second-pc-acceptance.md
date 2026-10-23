# R86 — second Windows computer: attended NO-NETWORK recovery acceptance

**User approval**: On 2026-10-17, user authorized an R86 test on their second Windows test PC. This narrowly authorizes a locally supervised, non-network SCM/mock Task Scheduler rehearsal, NOT WireGuardNT installation, real native VPN startup, Oracle changes, WFP modification, DNS, firewall or routing alterations. Real Windows/Oracle operations must not be executed remotely by CI or GitHub tools.

## Preconditions and package

Build the fixed `OracleProxy.R86.NoNetworkMock.exe` from `clients/windows/r86-field` on a disposable GitHub-hosted Windows runner. This is a deliberately **UNSIGNED** review-only .NET x64 Windows SCM mock whose code uses ServiceBase, ServiceController and local registry ownership verification. It does not load WireGuard/WireSock DLLs, open sockets, adjust adapters/routes/DNS/firewall/WFP, or access Oracle. CI must prove a real registered, LocalSystem running mock service stops at the deadline under a Windows SYSTEM one-shot Task Scheduler action, without the registrar process remaining alive.

Artifact `R86-SECOND-PC-NO-NETWORK-REVIEW-ONLY` contains exactly the mock executable, R86-Common, Preflight, Start, Verify, EmergencyCleanup scripts, README and SHA256SUMS. The workflow prints a SHA-256 for **each binary and script**. User must compare those immutable CI-log hashes against their downloaded extracted files; an included hash list alone cannot authenticate an artifact. Never request private VPN keys, account passwords, or active UU credentials.

**No bypasses**: Do not suggest disabling Defender, SmartScreen, Windows Firewall, UAC or PowerShell execution policy. If security software blocks the unsigned test exe or scripts, stop and assess or use a reviewed signed alternative. Never use a real production installer or load the existing WireSock driver.

## Physical machine execution protocol

User sits in front of the second Windows PC and opens *locally elevated* Windows PowerShell, not an RDP session. The tool verifies a local elevated admin process in the current active console session, 64-bit Windows, BFE and MpsSvc running, absence of exact-owned task `OracleProxyR86AutoStop`, SCM service `OracleProxyR86NoNetworkMock`, dedicated `ProgramData/OracleProxyR86Attended` directory, and test-specific old routes. A different existing service/task/root is a hard stop; no recursive deletion is attempted.

1. Extract GitHub CI package, compare all SHA256 values against the successful run's log, and run `./R86-Preflight.ps1`. It reads a compact SHA-256 of default IPv4/IPv6 routes, interface DNS and firewall rule count without printing addresses; it makes no changes.
2. With physically attended console and explicit confirmation, run `./R86-Start.ps1 -Confirm 'R86-SECOND-PC-NO-VPN-ONLY'`. It creates a dedicated strictly Administrators/SYSTEM-only stage and ownership marker, copies the fixed CI-built mock, writes random run token/UTC expiry and original network fingerprint; registers an exact SCM Manual LocalSystem no-network mock but DOES NOT start it yet.
3. Register the OS-owned one-shot SYSTEM scheduled action `OracleProxyR86AutoStop` executing the same owned mock executable's `--r86-expire <time> <token>` entry point approximately 3 minutes later. Verify task ownership, fixed binary and exact arguments. **Only after this succeeds**, start the mock SCM service and verify Running; if any step fails, attempt exact-owned cleanup.
4. Invoke `./R86-Verify.ps1` before and after timer expiry. After about 3-4 minutes, it requires native Task Scheduler's last run / exit code evidence, dedicated receipt, and stopped status of the precise mock SCM service, plus unchanged OS default routes/DNS/firewall fingerprint.
5. ALWAYS invoke `./R86-EmergencyCleanup.ps1`, regardless of outcome. It refuses foreign files, symlinks, ACL changes or a different service/task identity; unregisters only the exact task, stops only the exact owned mock if still Running, deletes the exact SCM registration and owned files and directory, and reports no residual. Then the operator separately confirms Internet and UU continuity on the physical machine.

## Security limitations

- Task Scheduler's one-shot worker performs a **mock service stop only** after verifying it runs as SYSTEM Session0, its exact deadline+random token, dedicated ownership marker, the binary's own SHA256 and the SCM local registry service ImagePath/LocalSystem/Manual mode. The worker does not auto-delete the task; cleanup does.
- This is a deliberately narrow 3-minute local test and cannot verify live WireGuardNT adapter removal, WFP fail-closed semantics, all-app IPv4/IPv6/DNS leak prevention, production privilege isolation, native field shutdown, reboot/power failure recovery or official WireSock coexistence while a native tunnel is connected. Ordinary network and UU continuity must be observed independently by the operator.
- The mock executable and scripts are not code-signed; published CI hashes provide traceability, not publisher identity attestation. The `-CiHarness` escape path is allowed ONLY when both `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, and `ORACLE_R86_CI=CI_ONLY`. Never set these on a physical computer.
- Any detected network fingerprint difference requires manual review rather than automatically resetting anything. There is NO license to mutate native OS network state or Oracle wg0/UDP/OCI NSG.
- R83 deliberately blocks `lab-field` native activation even with an accepted expiry lease; R86 does not weaken that gate. Production `UnavailableProductionKernel`, GA gate #34 and all separate real native field-test authorizations remain unchanged.
