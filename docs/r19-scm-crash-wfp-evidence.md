# R19 — kill the real LocalSystem manager; verify OS WFP persists

This is a disposable Windows GitHub-hosted **fault injection** only.

Reuses R18's real external TCP/443 and UDP/53 DNS socket baselines and
its single-program persistent WFP-backed outbound deny. Inside the existing
native WireGuardNT/SCM/G11 two-peer test, after real GUI-to-SYSTEM start,
handshake and tunneled synthetic UDP/DNS delivery:

1. Bind to the exact SCM manager *created by this test*; obtain SCM PID and
   check that the executable full path matches the CI-built manager.
2. Force-kill that LocalSystem manager process. The command cannot target
   any different service PID or binary. Confirm the service is Stopped.
3. Confirm both actual WireGuard peer services remain Running after their
   manager crashes.
4. Re-read the original WFP rule from Windows' ActiveStore and prove fresh
   public IPv4 TCP and raw external UDP DNS still fail for the test process.
5. Exercise job-independent emergency cleanup to stop only CI-owned peers,
   delete adapter/routes/configs/keys, then explicitly remove only the exact
   WFP filter and confirm TCP and DNS connectivity recover.
6. Check persistent Windows Firewall rule count/profile state and IP route
   baseline. Hosted CI runner is discarded on completion.

**Limitations:** The guard is installed by a separate test PowerShell
process, not by the manager; this confirms a persistent **OS-owned rule can
outlive a manager process crash**, not that the future production service
successfully installs or recovers a whole-device policy. The packet rule
targets one program; no physical UU direct arbitration, full IPv4/IPv6/DNS
leak proof, restart/boot validation or user-accepted rescue mechanism.
No production connect activation or Oracle/WireSock/UU changes. #34 remains.
