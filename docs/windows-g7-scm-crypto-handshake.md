# G7: Real official embeddable WireGuard tunnel Windows SCM service lab

**Disposable GitHub-hosted VM only, not a usable VPN client or fail-closed protection.**

We previously proved a genuine WireGuardNT kernel handshake in G6 by direct
adapter API calls. G7 adds a different integration path: the actual
source-built upstream `tunnel.dll` is loaded by the C# x64
`OracleProxy.WireGuardHost.exe` running as a manually started Windows SCM
service named `WireGuardTunnel$lab-peer-a` or
`WireGuardTunnel$lab-peer-b`.

Each service is installed with `Nsi` and `TcpIp` dependencies and
`SERVICE_SID_TYPE_UNRESTRICTED`, as required by the official upstream
embeddable DLL service contract. A separate signed WireGuardNT 1.1 DLL is
also present. Nothing is deployed to Oracle or the user's critical Windows PC.

## Safety gates

- Restricted to an internally authored PR branch on disposable
  `windows-latest`, not fork PRs or persistent Windows machines.
- Both private keys generated anew for each attempt, written only in runner
  temporary files and private `%ProgramData%\OracleProxyLab\config` paths.
- Both test endpoints are `127.0.0.1`, fixed UDP 52741 and 52742.
- Both configs use fixed `10.249.129.1/32` and `10.249.129.2/32` addresses
  and only the peer /32 as AllowedIPs; no `0.0.0.0/0`, `::/0`, DNS setting,
  global proxy or firewall modification is requested by our scripts.
- Before native loading, the host checks allowlisted profile name,
  SHA-256 manifest, safe file sizes, absence of command hooks, and
  protected Windows NTFS directory and file owner/DACL.
- Built from official WireGuard source pinned to
  `6ece77bc487c8aa697e3c092197621c4f3e5ccb8`; signed WireGuardNT 1.1
  DLL hash and MinGW toolchain SHA-256 are independently pinned.
- A separate read-only native observer opens existing adapters and polls
  both **kernel-provided LastHandshake values**, rather than relying on an
  SCM Running state alone.
- Each service is `StartType=demand`, and teardown stops/deletes only these
  two fixed service names. Only files created by the job's ownership
  marker may be deleted; keys are removed unconditionally afterward.
- Pre/post default IPv4 and IPv6 route snapshots are compared.
  GitHub destroys the entire ephemeral VM regardless of lab success.

A GitHub-hosted runner **does not** provide a user-operated hypervisor
snapshot/console and is not an acceptable place to test persistent WFP
blocking or UU/remote-control continuity.

## What remains

This is a localhost-only real tunnel-service and handshake experiment.
It does **not** establish external Oracle connectivity, secure production
installation, real GUI-to-service VPN control, verified DNS/IPv6 no-leak,
selective UU process bypass or crash/boot fail-close.

The source-built `tunnel.dll` is **unsigned**: it is not uploaded as an
artifact and cannot be redistributed as a production VPN package without
licensing/signing/provenance review.

If the Go tunnel service cannot start safely due VM restrictions or OS
service ACL details, CI must fail rather than modify the user's WireSock or
Oracle deployment.
