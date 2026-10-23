# R53 — Investigate R51 physical field baseline failure before any more WFP changes

## Actual physical second-PC evidence, Oct 16

The physical PC successfully ran the disabled-rule SYSTEM auto-undo canary
(`R51_SYSTEM_AUTOUNDO_CANARY_PASS`). Later, manually pasted commands
produced `R51_BASELINE_UNAVAILABLE` before any enabled WFP rule could be
created. The succeeding top-level `Write-Host 'R51_BASELINE_TCP_PASS'`
was a **misleading manual print**, not a valid proof: PowerShell continued
executing subsequent pasted statements after a top-level throw. A
`finally` block pasted separately was rejected by the parser. The
resulting watchdog was subsequently cleared; the operator confirmed
`R51RulesRemaining=0`, `R51TasksRemaining=0`,
`R51CleanupComplete=True`.

**Do not claim any physical IPv4 TCP443 blocker was observed.**
No normal networking, DNS, UU, WireSock or Oracle changes are necessary.

## Change

A new `R53-CopyPasteReadOnlyTcpBaseline.txt` contains one complete,
single, outer `& { ... }` PowerShell scriptblock. On an interactive
PowerShell 5.1 console, pasting the **whole** block will keep the shell
in continuation mode until its final brace. A thrown error stops the
contained block and does not leave separate success-printing commands.
Do not copy the plain-text source as a .ps1: the field PC correctly uses
the built-in `Restricted` execution policy.

The block makes two direct IPv4 TCP 443 socket attempts, using at most
2.5 seconds per attempt, to each of five fixed public literal IPs:
`1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `9.9.9.9` and
`208.67.222.222`. It never resolves DNS names or tests additional
destinations. It emits one JSON report showing only the five publicly
known destinations, per-destination success counts (0..2), and
`network_mutation_performed=false` /
`production_vpn_authorized=false`. The probe refuses if the previous
R51 rule or recovery task exists.

Windows CI parses the **actual copy/paste text** with Windows PowerShell
5.1, runs it, validates the report, and independently checks that the
Windows Firewall rule inventory and Task Scheduler inventory did not
change. A CI target's reachability is not assumed to match the user's
network: a failure of all five fixed targets on a real PC is a valid
reason to STOP mutation tests and choose another diagnostic approach.

## Required additional authorization

If one or more targets are consistently reachable on the field PC, the
operator must still review a new **exact single-target** active-rule
transaction that uses that fixed address, verifies that the address is
not configured as the PC's DNS, and performs an independently scheduled
SYSTEM canary before enabling anything. Never reuse the old hard-coded
`1.1.1.1` rule blindly. The results of R53 do **not** themselves
authorize any firewall modification.

No relaxing PowerShell execution policy, running unsigned .ps1,
installing VPN drivers, touching Oracle, WireSock, UU, or broad
IPv4/IPv6 WFP policy. Production `UnavailableProductionKernel` and
release blocker #34 stay in place.
