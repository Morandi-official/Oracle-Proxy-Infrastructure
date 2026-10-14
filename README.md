# Oracle Proxy Infrastructure

**Status: experimental Windows VPN source and cloud test infrastructure. NOT a
released VPN product.** Do not use these development binaries to replace
WireSock or for important UU remote sessions.

This repository now hosts the working source baseline consolidated from the
previous stacked engineering branches. The default Windows GUI build is
read-only, not a production connect/disconnect client. Privileged tunnel
controls are allowed only in explicitly isolated disposable GitHub CI labs.
The CI-only administration build must not be redistributed.

## Verified engineering capabilities (cloud labs only)

| Gate | Narrow result | Critical limitation |
| --- | --- | --- |
| G13 | Linux kernel WireGuard across three separate network namespaces; IPv4/IPv6, synthetic DNS and link outage | One cloud VM, not two independent public hosts |
| G14 | Real Windows WireGuardNT app UDP send/receive and synthetic DNS | Two peers on one hosted Windows VM |
| G17 | Windows native IPv6 application UDP and DNS AAAA in tunnel lab | No external IPv6 or Windows DNS leak proof |
| R4 | In-memory authorized intent planner, reject replay and implicit OFF | Not connected to production SCM or WFP |
| R5 | Temporary status-only LocalSystem service install/GUI IPC/uninstall | Not a functional VPN installation |
| R6 | Stop real test WireGuardNT peers, remove adapter and routes, check DNS/firewall baseline | Narrow routes only, no OS fail-closed |
| R7-R8 | Windows WFP-backed scoped filter lifecycle and real IPv4 TCP deny/restore | Not a whole-device kill switch; external IPv6 baseline unavailable |
| R9 | Read-only candidate-port inspection for existing Linux server | No server SSH access or sidecar deployed |

Evidence is linked in docs/source-baseline-status.md.

## Build and safety

Windows manager and GUI projects (Windows 11 x64, .NET 8):

- clients/windows/manager/OracleProxy.LabManager.csproj
- clients/windows/app/OracleProxy.Windows.Preview.csproj

The Windows release preview MUST build with
EnableDisposableLabControls=false (default) and must not package
tunnel.dll, wireguard.dll, any private key, test configuration or CI manager
that can start tunnels. See docs/windows-release-criteria.md.

Native WireGuardNT and official WireGuard Windows tunnel sources are used in
CI with upstream pins. Attribution, binary provenance and license obligations
need full review before any distributed product is offered.

**Never run** scripts under clients/windows/lab, lab/wfp-scoped, or
lab/windows-packaging on a production PC. Some scripts deliberately create
real temporary firewall rules and SCM tunnel services, but are hard-gated
to disposable GitHub-hosted runners. Never try to bypass these gates.

## Still blocking functional Alpha and general availability

1. An audited, protected installable native WireGuard engine and authorized
   production GUI-to-SYSTEM control path (the current live control is CI-only).
2. Actual durable fail-closed WFP enforcement for IPv4, IPv6, UDP/TCP, DNS
   and startup/crash/reboot, proven by independent packet captures.
3. Safe OFF, uninstall and emergency rollback under real outages.
4. True two-host cross-network transport, independent recovery console,
   and verified UU remote-control continuity without bypass mistakes.
5. Signed installer/uninstaller, third-party notices, secret lifecycle,
   reproducible release artifacts and final security signoff.

**No production Release should be created or called WireSock-compatible
until these gates are demonstrated.** GitHub Actions green checks verify
only each named, narrowly scoped test.

Project branches are historical engineering evidence. The main branch is
intended to track source code, not an installed VPN. Any future public
release must use reviewed release gates in release/.

No local hypervisor installation or purchase of a new Oracle instance is
required for the cloud tests in this repo. The existing Oracle server,
WireSock and UU remain outside all CI experiments.
