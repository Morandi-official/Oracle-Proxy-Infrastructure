R86 — SECOND WINDOWS PC: SUPERVISED NO-NETWORK MOCK ONLY

IMPORTANT: This is NOT a VPN. It must not install, load, configure, or
connect WireGuardNT, WireSock, firewall rules, IP routes, DNS, or Oracle.
Requires a physically present operator at the Windows machine, a locally
elevated Windows PowerShell console, and a verified GitHub Actions artifact.
Do not proceed from an RDP session. Do not disable Defender, SmartScreen,
ExecutionPolicy, Windows Firewall, or UU to run any step.

IMPORTANT: This package contains an UNSIGNED self-contained .NET Windows
service used solely to exercise a three-minute OS-scheduled auto-stop.
It is a narrow lab executable, NOT a signed installer or production release.
If Defender/SmartScreen/ExecutionPolicy blocks it, STOP and report the error
rather than bypassing system protections.

Service name: OracleProxyR86NoNetworkMock
Task name: OracleProxyR86AutoStop
Dedicated directory: %ProgramData%\OracleProxyR86Attended
Automatic mock stop: around three minutes after script Start, via Windows
Task Scheduler, SYSTEM account, independent executable, exact fixed name.
The stop task does not delete itself. EmergencyCleanup deletes only the
verified owned service, scheduled task and dedicated files afterward.

BEFORE running: compare the SHA256 of each package file against the
corresponding SHA256 values in the completed official GitHub CI job's log.
The package's own SHA256SUMS.txt is only an aid and is not independently
authenticated. Never run unknown or modified files.

In a LOCAL elevated Windows PowerShell window with current directory
set to the extracted package:

  .\R86-Preflight.ps1
  .\R86-Start.ps1 -Confirm 'R86-SECOND-PC-NO-VPN-ONLY'
  .\R86-Verify.ps1

The first Verify should show RUNNING before expiry; wait approximately
3-4 minutes after Start and run Verify again, expecting SYSTEM_STOPPED.
Finally ALWAYS run:
  .\R86-EmergencyCleanup.ps1

If the service remains running or an error appears, run the same
EmergencyCleanup immediately and share only nonsecret error messages.
Check regular Internet and UU manually afterward. Report results to the
assistant. Do not try any native VPN test without separate approval.

CI code includes -CiHarness exclusively gated by a verified hosted
GitHub Actions context. NEVER use or set ORACLE_R86_CI on a real PC.
