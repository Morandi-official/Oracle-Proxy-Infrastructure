# R51 — Attended second-PC field acceptance (bounded, recoverable)

## Authorization and permitted scope

The operator explicitly approved a supervised, locally recoverable test
on the separate noncritical Windows computer. This does NOT authorize
changes to Oracle, WireSock, UU, full-device WFP, global Internet routes,
system DNS, VPN adapters, or production safety gates.

Stage 0 is **read-only**. Confirm you can physically operate the local
keyboard and screen, have a locally elevated Windows administrator account
and can recover the computer without remote-control or the tested network.
Do not treat a remote desktop session as local recovery. BFE, MpsSvc,
Task Scheduler and Windows Firewall profiles must be running, and the
target must not be configured as the computer's system DNS server.
The field probe refuses pre-existing lab rule/task names.

Stage 1 is a separate, **optional, locally authorized** test after these
checks, not something to run blindly on a daily-use computer. It creates
a system-level scheduled auto-undo task with *both* a short deadline and
an AtStartup trigger, then creates a **disabled** exact-name Windows
Firewall rule for 1.1.1.1 TCP destination port 443 ONLY. It triggers the
SYSTEM recovery task immediately and requires actual removal before
the enabled rule can ever be created. Failure aborts before blocking.

Stage 2 creates that one enabled rule, checks its exact TCP443 scope,
requires two fresh TCP connections to be denied, and invokes the
SYSTEM rollback task. It verifies exact owned rule/task removal,
restored direct TCP connection, unchanged default IPv4/IPv6 routes and
DNS settings. A test failure never resets unrelated network policy.

## Human recovery if the test UI terminates

At the physical keyboard, in *elevated* PowerShell:

1. Inspect the only lab rule with Get-NetFirewallRule -Name
   'OracleProxy-R51-Attended-TCP443-1.1.1.1'.
2. Run Start-ScheduledTask -TaskName
   'OracleProxy-R51-SafetyAutoUndo' if the task still exists.
3. If the task is unavailable but the exact rule exists, use
   Remove-NetFirewallRule -Name
   'OracleProxy-R51-Attended-TCP443-1.1.1.1'.
4. Verify the exact rule no longer exists, test normal Internet, then
   unregister only the task with Unregister-ScheduledTask -TaskName
   'OracleProxy-R51-SafetyAutoUndo' -Confirm:$false.
5. Do not disable Windows Firewall, run netsh reset, delete other VPN
   adapters, stop UU/WireSock, or change default routes.

The script itself has no system execution-policy changes. Because the
second PC previously reported that .ps1 execution was blocked, operator
steps should start with manually pasted read-only PowerShell commands;
do not globally change execution policy or bypass domain policy.
Only choose a separately approved execution method AFTER the operator
confirms local recovery access and the CI proof is successful.

## What the test can and cannot prove

Can prove: Windows Firewall actually denies new IPv4 TCP443 sockets to
one fixed external host, a separate elevated SYSTEM scheduled task
can remove a disabled test rule and subsequently remove an active rule,
and direct connections recover without route/DNS edits.

Cannot prove: full-device physical IPv4/IPv6 TCP/UDP/DNS WFP coverage,
UU remote-control continuity under VPN, genuine second-host WireGuard,
power-loss recovery in all Windows task-scheduler failure modes,
signed production installer or cryptographic end-user release consent.
The production manager still uses the deny-only kernel.
GA blocker Issue #34 stays open.
