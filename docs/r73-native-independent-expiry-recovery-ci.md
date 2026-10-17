# R73 — independent expired native lab peer stop after manager crash (hosted Windows CI)

R71 physical read-only acceptance succeeded. R72 constrains a future public single-peer field-trial proposal but never approves a real network connection. R73 improves the existing native CI runtime cleanup evidence before ANY physical VPN test is authorized.

## Executed scope

On a disposable GitHub-hosted Windows VM, the existing G14 lab still builds pinned genuine upstream native WireGuardNT components, protects two synthetic peer configs, starts two real SCM tunnel services using admin-authenticated GUI -> LocalSystem manager IPC, and demonstrates native UDP + tunnel-local DNS A/AAAA with increasing peer transfer counters.

Only in the R73 branch's CI build, after application traffic has passed, the runner checks the **exact manager binary path** and forcibly terminates only the CI-created manager process. It independently confirms the two native SCM tunnel services are still active, exercises a too-early deadline refusal, then launches a **separate PowerShell process** to execute `clients/windows/lab/Invoke-R73CiOwnedExpiryRecovery.ps1` with an expired UTC timestamp.

The independent recovery script requires exact hosted runner environment and CI opt-in, both creation/approval markers, a strictly formatted UTC deadline due no more than five minutes ago, and both exact `WireGuardTunnel$lab-peer-a/b` LocalSystem manual service names with separately verified binary paths. **Every** precondition is checked before stopping either tunnel. It stops only those two services, checks their Windows SCM states, and waits for their fixed /32 and /128 synthetic routes to disappear. Existing workflow always-run cleanup must still remove all owned SCM services, configs, native driver files, keys and restore baseline Windows default routes, DNS and firewall.

## What this proves and what it does NOT

If CI succeeds, it proves that on this disposable Windows runner an explicitly invoked **independent process** can stop two exact owned native lab tunnels after management-process death, without needing GUI/IPC. It does **not** demonstrate a registered OS scheduled-task watchdog, automatic timeout after a GUI crash, boot/startup recovery, safe network restoration on a real physical computer, or real external peer reachability. There is no WFP installed/released as part of the new recovery primitive; it **cannot** prove full-device fail-close, UU P2P/relay continuity or production safe Off.

The new script is CI-only and refuses real-PC execution. It must never be copied and manually forced onto the user's UU/WireSock Windows computer. Production `UnavailableProductionKernel` and GA blocker #34 remain untouched. Actual Oracle temporary public endpoint / Windows native installation require fresh operator approvals after a more complete recovery design and independent validation.
