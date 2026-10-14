# R22 — tampered OS WFP rule stops real CI tunnel peers

This experiment extends R21 on a disposable GitHub-hosted Windows runner.

The real LocalSystem manager uses a narrow, compile-time opt-in WFP guard
that applies **only to the hosted PowerShell probe process**, not to a
user's whole network. R22 changes the manager to ask Windows Firewall COM
for the actual rule before every CI tunnel Start request and every 750 ms
during a running session. An absent or altered rule is latched as compromised;
the manager invokes Stop on the two fixed disposable WireGuard SCM services,
and will refuse further Start requests.

The fault-injection sequence is real: an elevated *test* process verifies a
genuine SYSTEM-created process-specific WFP rule, proves actual external TCP
and raw DNS blocking, allows the authenticated GUI to start both genuine
WireGuardNT peers and pass tunnel UDP/synthetic DNS, deletes only that exact
CI-owned COM rule, waits for both Windows tunnel services to stop, and
confirms an otherwise authorized GUI start request is rejected. It verifies
scoped services/routes/keys and network/firewall baseline recovery.

**Not production fail-close.** A 750 ms poll is not packet-atomic: when a
privileged administrator deletes the OS WFP rule, packets may escape before
the watchdog stops the tunnel. It also does not cover service death,
machine boot/reboot or whole-device physical IPv4/IPv6/DNS traffic. The
production security gate stays closed. Hardening requires OS-level persistent
per-interface enforcement and trusted endpoint/UU exception handling. None
of these experiments affects the user's Oracle VM, WireSock or UU remote PC.

Tracks release blocker #34.
