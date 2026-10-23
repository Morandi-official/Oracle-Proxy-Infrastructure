# R52 — Active physical console session instead of SESSIONNAME

The supervised second Windows test PC reported an elevated PowerShell
process with `SESSIONNAME` not equal to `Console`, even though a
read-only native check returned:
`CurrentSession=1`, `PhysicalConsoleSession=1`,
`SameConsole=True`.

The environment variable is **not an authoritative console-session
attestation**, especially after UAC elevation. R52 changes both R51
read-only preflight and attended live-test guard to use Windows
`kernel32!WTSGetActiveConsoleSessionId`, compared with
`Process.GetCurrentProcess().SessionId`. Unavailable API calls, errors,
or the special unsigned 0xFFFFFFFF console-transition response fail
closed. The human's explicit approval string, locally elevated
Administrator token, BFE/MpsSvc/Schedule status, no-existing-rule
requirements and independent SYSTEM auto-undo proof remain required.
The attended mode cannot automatically start a VPN, make routes, alter
UU/WireSock/Oracle, or change system DNS.

The R52 hosted Windows workflow executes Windows PowerShell 5.1
read-only preflight, missing approval denial, a separate non-console
denial when the runner actually is non-console, and the original
independent SYSTEM task canary + real single-host TCP443
block and exact restoration regression.

**On the supervised PC, execution policy remains Restricted.**
This stage does not ask the operator to run an unsigned .ps1 or relax
the policy. Actual field mutation will only be proposed as reviewed
interactive commands, staged and confirmed while physically present.
Native WTS matching is one input, not proof against all remote session
tricks or adequate authorization for production WFP release.

No driver install, production WireGuard start, broad firewall rule,
Oracle server, UU or WireSock modification. Issue #34 remains the
launch blocker.
