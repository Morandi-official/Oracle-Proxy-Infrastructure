# Windows G3 — official WireGuard embeddable service host (LAB ONLY)

This is a **real native interop bridge** to the official WireGuard
`WireGuardTunnelService(LPCWSTR)` export in `tunnel.dll`, using the x64
Windows service-host integration approach described by upstream.

**It is NOT an installed/working VPN service yet.** The GitHub build contains
the host program and offline integrity tests **but never bundles**
`tunnel.dll`, `wireguard.dll`, private keys, VPN configs, installers,
service-creation scripts, or WFP/network filtering components. The integration
path has not yet been validated with the actual signed WireGuard binaries or
a real lab tunnel. No IPC or GUI-to-service command channel exists yet.

## Confirmed official contract

- https://www.wireguard.com/embedding/
- https://github.com/WireGuard/wireguard-windows/blob/master/embeddable-dll-service/README.md
- Service name pattern `WireGuardTunnel$SomeTunnelName` with dependencies
  `Nsi`, `TcpIp`, service SID `SERVICE_SID_TYPE_UNRESTRICTED`, and a dedicated
  service process
- Export `BOOL __cdecl WireGuardTunnelService(LPCWSTR configurationFile)`
- Built `tunnel.dll` depends on an appropriate `wireguard.dll`

Upstream repository is MIT licensed. Binary provenance, DLL/driver license
terms, hashes, Authenticode signatures and redistributable notices require a
separate review before distributing any DLL.

## Deliberately narrow runtime command

- `OracleProxy.WireGuardHost.exe --self-test`: harmless offline checks.
- `OracleProxy.WireGuardHost.exe --wireguard-service`: **real native
  entrypoint**, but refuses invocation unless run as SYSTEM in Session 0,
  a separately installed SCM service. It takes NO untrusted tunnel name,
  executable path or configuration path arguments.

The only considered lab profile filename is `lab-only.conf`, under
`%ProgramData%\OracleProxyLab\config\lab-only.conf`. The manifest
`engine-pins.json` must exist next to the dedicated host executable and pin
the SHA-256 values of `tunnel.dll`, `wireguard.dll`, and the lab config.
Script hooks are rejected. No DLL loads when hashes fail or files are absent.

Example **schema only**, with no real keys/hashes:

```json
{
  "schema_version": 1,
  "tunnel_sha256": "64 hexadecimal characters",
  "wireguard_sha256": "64 hexadecimal characters",
  "config_sha256": "64 hexadecimal characters"
}
```

**Not a production security guarantee:** hashing files against a manifest
in the same directory does not establish provenance, secure file ownership,
ACL protection, or trusted publisher identity. The code presently does
not verify Authenticode publisher chains or all parent-directory reparse
points, and does not pin a vendor-signed binary release version. The missing
secure lab installer is an intentional blocker to real activation.

## Real Windows Service Control Manager observation (read-only)

The host also supports `OracleProxy.WireGuardHost.exe --service-status`.
This calls Windows `OpenSCManagerW`, `OpenServiceW`, and
`QueryServiceStatusEx` with **query-only permissions** for the single fixed
lab service `WireGuardTunnel$OracleProxyLab`. It does not enumerate other
services, start/stop any service, ask for elevation, or change a setting.

The output is sanitized JSON: service name, service state (including
`absent`), and explicit `false` flags for handshake verification and
actual fail-close verification. A running SCM service does **not** prove
any WireGuard peer has handshaken.

GitHub Windows CI tests this real read-only SCM query on its disposable
runner; it does not register any tunnel service.

## CI safety

GitHub Actions builds a self-contained win-x64 executable and calls
`--self-test` on a disposable hosted Windows runner. It also verifies
that a non-SYSTEM process cannot launch the real service mode. The service
is **not registered** and no VPN driver or firewall rules are installed.

The artifact is a security-review prototype, not a deployable client.
Never run it on the UU-remote-controlled Windows computer.

## Next real integration gates

1. Independent installer and package provenance review with Microsoft
   service-control/Service SID security checks and protected directories.
2. Protected on-device generated WireGuard keys and isolated **new** lab peer.
3. Real SCM launch with the official DLLs on an isolated Windows lab VM,
   including start, handshakes, service crash and controlled rollback.
4. Authenticated local IPC based on caller OS token and service ACLs.
5. Only **after** the above: isolated WFP rule tests, UU IPv6 UDP P2P
   continuity, DNS/IPv4/IPv6 leaks and boot-time fail-close recovery.

Do not mistake a library-call ABI bridge for proven fail-closed behavior.
