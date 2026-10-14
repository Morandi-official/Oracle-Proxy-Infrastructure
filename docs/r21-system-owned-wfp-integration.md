# R21: SCM LocalSystem installs real persistent WFP-backed guard

This is a disposable hosted Windows integration experiment only. The
**actual LocalSystem manager service process** now uses Windows Firewall's
INetFwPolicy2/INetFwRule COM APIs (rather than launching PowerShell) to add
a persistent, fixed-name, fixed-application outbound deny rule for ONLY
the known GitHub CI PowerShell 7 executable. It spans protocols, destination
ports and remote IPv4/IPv6 addresses for that **one executable**.

The implementation lives wholly behind a compile-time CI-only switch and
a new strictly bounded service launch mode. A normal release manager binary
cannot compile in or launch the privileged filter installer. It requires
the protected GitHub-lab marker and Windows SYSTEM Session 0 identity and
refuses to replace a preexisting rule.

On the disposable Windows runner:

- Baseline real TCP/443 and raw UDP/53 DNS reachability before service start.
- Register real independent SYSTEM service and native WireGuard lab peers;
  the manager installs its WFP rule **before starting any IPC listener**.
- Check exact active WFP protocol, application and action, then prove both
  external TCP and direct UDP DNS denial before tunnel start, while genuine
  encrypted tunnel handshakes and synthetic application DNS packets flow.
- Force-kill the exact CI-created LocalSystem manager PID with executable
  path verification. The persistent rule must remain in Windows ActiveStore
  and continue denying TCP/UDP DNS after the manager crash.
- Independently clean CI-owned native peer SCM services, protected config,
  adapters/routes/key material, explicitly remove only this fixed rule and
  verify direct TCP/DNS recover plus original firewall/route/DNS state.

**Critical limitations**: This does NOT globally protect Windows network
traffic, is not a physical-interface-aware exception mechanism for UU,
does not guarantee protection during system boot/reboot or Windows BFE
failure, and does not create production VPN controls. The rule excludes
other executables by design so CI connectivity remains intact. User
acceptance and packet captures on a separately recoverable host are still
required. Do not run any R21 executable on Oracle or the real UU/WireSock
Windows machine. Issue #34 remains blocked.
