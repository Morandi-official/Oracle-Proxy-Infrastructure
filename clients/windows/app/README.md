# Oracle Proxy Windows v0.2 — unsigned, portable, read-only user test

**This is a genuine standalone Windows desktop application, but not yet
a working VPN, Oracle proxy or replacement for WireSock.** It does not
create a VPN tunnel, forward Internet traffic, install a driver, add WFP
rules, change routes, change DNS, or take over UU remote control.

It is offered so users can **try the GUI on their own Windows PC today**
without risking the computer's network. The release-blocking all-device
WFP and safe production Off are **not implemented**.

## What v0.2 can actually do

- Open a real native .NET 8 WinForms graphical app without elevation.
- Refresh local, sanitized OS diagnostics using **C# + native Windows
  APIs**, without launching PowerShell or changing `ExecutionPolicy`.
- Read the set of active Ethernet/Wi-Fi **candidate** interfaces and
  OS IP Helper IPv4/IPv6 default-route/interface association, with no
  IP address, gateway, DNS server, interface index or MAC emitted.
  Candidate interfaces are not a proof of physical ownership.
- Read three fixed known Windows service/driver states using read-only
  Service Control Manager requests and the presence of the allowlisted
  UU GameViewerServer process by name only.
- Show offline WFP fail-close policy simulations, clearly labeled
  **NOT active Windows network protection**.
- If a separately installed status-only experimental SCM service exists,
  read its OS-authenticated pipe status and exercise *negative safety
  checks*. Otherwise show a clear "service unavailable" message.

## Try without installation

1. From GitHub Actions `Windows release isolation and unsigned preview
   package`, download artifact
   `oracle-proxy-windows-v0.2-UNSIGNED-READONLY-TEST-win-x64`.
2. Open the downloaded ZIP and inspect `READ_ME_FIRST.txt` and
   `build-manifest.json` before running anything. The manifest contains
   a SHA-256 hash of the one executable.
3. Extract the package to a new ordinary folder on an **independently
   accessible, noncritical** Windows 10/11 x64 PC.
4. Double-click `OracleProxy.Windows.Preview.exe` normally, as a regular
   user; do NOT choose Run as Administrator. Refresh diagnostics.
5. Close the window and delete the extracted folder to remove this
   portable preview. It adds no SCM service, startup task, firewall rule,
   driver, VPN profile, proxy setting or persistent install.
6. If Windows security policy or SmartScreen blocks this unsigned build,
   **stop**. Do not disable protection, lower script execution policy or
   bypass endpoint protection for this experiment.

`--self-test` and `--diagnostics-self-test` are optional CLI
selftests, not VPN connections. The GUI will NOT tunnel Oracle traffic.

## Evidence and precautions

GitHub Windows hosted CI builds the x64 executable, runs real Windows
native route/SCM/UU diagnostics under a Restricted-policy runner
environment, executes policy/control protocol regression tests,
excludes native drivers, power-shell scripts and CI-only tunnel code
from the download, and packages SHA-256 evidence. This is not a
physical Win11 graphical usability test, a production signing audit,
or proof of real UU continuity.

Your second Windows test PC has previously experienced intermittent
browser connectivity and blocked direct-public-IP TCP443 baselines.
Do not run WFP/mutating diagnostics there as part of trying this GUI.
No VPN or proxy connection will be attempted by this v0.2 build.

R42–R50's true SYSTEM/WireGuardNT/WFP tests remain separate, fixed-
destination disposable GitHub Windows experiments. Those are
**not shipped** in this test app. GA issue #34 remains OPEN.
