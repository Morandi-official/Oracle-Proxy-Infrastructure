# G6 — disposable Windows VM WireGuardNT localhost handshake laboratory

**Experimental, never for the remote UU machine.**

The previous G4/G5 stages proved that an independent privileged Windows
Status-only service can run and that real signed official `wireguard.dll` /
source-built `tunnel.dll` can be loaded and their ABI inspected. They did
**not** actually handshake.

This G6 test uses the official **signed WireGuardNT 1.1 kernel interface**
directly, on GitHub-hosted Windows only, to check whether two ephemeral,
locally hosted WireGuard peers can complete cryptographic handshakes.

## Isolation

- Two temporary WireGuardNT adapters named `OracleLabTestA/B`, both within
  the one disposable GitHub-hosted Windows VM, are allowed.
- Only localhost endpoints `127.0.0.1:52741/52742`.
- Peer allowed IPs are two /32 test addresses (`10.249.129.1/32` and
  `10.249.129.2/32`). No default routes, DNS, firewall or WFP changes.
- Real X25519 keys are generated fresh inside runner temp and never emitted,
  checked in, uploaded or sent to Oracle.
- The harness verifies **both sides' genuine driver LastHandshake values**,
  not just an adapter reporting 'Up'.
- It always attempts to bring test adapters down, close their handles and
  remove the driver if it was not already present. GitHub's independent VM
  disposal supplies the final recovery boundary.
- CI refuses the experiment if the runner is not GitHub-hosted, the account
  is not administrator, or the named test adapters are preexisting.
- The native signed driver and compiler are SHA-256-pinned to the upstream
  WireGuardNT 1.1 SDK and archived LLVM-MinGW, as independently tested in
  PR #9. Nothing native is uploaded as a release artifact.
- The test must not run for forked PRs, persistent machines, Oracle production
  endpoints or any UU-controlled Windows computer.

## Limits

This is **not yet an actual `WireGuardTunnelService` SCM service launch**.
The experiment invokes the underlying signed WireGuardNT adapter APIs
directly, and service start/stop integration remains a separate acceptance
gate. A local handshake also does not establish that a VPN client can connect
through an ISP to Oracle, nor that fail-close, DNS/IPv6, or UU split tunneling
is safe.

A GitHub-hosted runner is ephemeral and independently discarded after the
job. It does **not** provide a user-controlled hypervisor snapshot/console,
so no production-like WFP testing is permitted in it.

If the Windows runner refuses signed driver installation, or the local
handshake cannot be independently observed, the test must FAIL and report
that blocker without falling back to the existing WireSock/Oracle setup.

References:
- https://github.com/WireGuard/wireguard-nt
- https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip
- https://github.com/WireGuard/wireguard-windows/blob/master/embeddable-dll-service/README.md
