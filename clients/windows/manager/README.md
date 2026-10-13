# Windows LabManager — actual SCM service, STATUS ONLY

This is a functional `.NET 8` Windows service **runtime**, but it is NOT a
VPN control service or kill switch. It is intentionally a separate process
from the future `WireGuardTunnel$OracleProxyLab` tunnel service and does
not contain or load any native VPN DLL.

## Implemented / tested

- `--manager-service` requires **LocalSystem** in Windows Session 0 and
  runs `ServiceBase.Run` under the SCM. The service is named exactly
  `OracleProxyLabManager`.
- A local named pipe with an **explicit protected Windows DACL** permits
  LocalSystem and local Administrators only. The server impersonates its
  caller using `RunAsClient`, inspecting a real Windows-issued identity
  token instead of trusting any claimed JSON fields.
- The sole control request is
  `{"protocol_version":1,"command":"Status"}`. All mutating commands,
  unknown fields and malformed requests are rejected.
- Client input is capped at **512 UTF-8 bytes before decoding**, with a
  four-second read deadline. Responses expose no user paths, keys, peer
  addresses or process IDs.
- `--ipc-self-test` opens an actual local Windows named pipe with
  `CurrentUserOnly` strictly for disposable CI. The real service path
  always uses SYSTEM/Admin ACL and OS identity checks.
- `--ipc-status` connects to the installed lab service without invoking
  service control APIs or touching drivers.

GitHub Windows CI registers the **status-only** manager with the SCM on
a disposable hosted VM, starts it, queries it, then stops and deletes it.
It never installs `wireguard.dll`, creates a VPN tunnel, adds any WFP
filter, or changes the live Oracle server.

## Critical security restrictions

This application DOES NOT allow Start/Stop/Install of the actual WireGuard
service, edit configs, flip user intent, or execute shell commands. It
does not persist VPN intent and cannot enforce traffic fail-close.

A SYSTEM service responding to Status does **not** establish readiness for
privileged tunnel management. In a later review we must implement:
- authenticated, narrowly scoped *mutating* IPC after security review;
- protected persisted user intent and independent startup recovery;
- actual signed/binary-pinned embeddable `tunnel.dll` and driver licensing;
- isolated real handshake, disconnection, DNS/IPv4/IPv6 leakage tests;
- physical UU UDP/IPv6 remote continuity under WFP policy.

**Do not install this experimental unsigned service on the critical
UU-controlled computer.** The source and CI tests are for review only.

Evidence and upstream pins: `docs/windows-lab-gates.md`.
