# Pinned WireGuard tunnel.dll source-build/export verification (G5 candidate)

Goal: use a GitHub-hosted disposable Windows runner to compile **genuine
upstream** embeddable `tunnel.dll` from an immutable WireGuard source commit,
load that DLL and inspect the exported `WireGuardTunnelService` function.

This exercise is explicitly **NOT** an attempt to launch a tunnel, install
`wireguard.dll`, register an SCM tunnel service, or connect to Oracle.

## Exact upstream dependencies pinned

- Official upstream: `WireGuard/wireguard-windows`
- Source commit: `6ece77bc487c8aa697e3c092197621c4f3e5ccb8`
- Go: `1.27.1` (as required by source's pinned Windows build script)
- Cross compiler: official WireGuard toolchain mirror
  `llvm-mingw-20260311-ucrt-x86_64.zip`
- Compiler archive SHA-256:
  `dd4c67d98959479c7be2fb6709ba074475991590848cb9d0eb2620be06b182e1`
- Build: AMD64 only, `go build -buildmode c-shared` and the upstream
  source's `.overlay/overlay.json`

The experiment uses native compiler toolchains downloaded by GitHub Actions,
not a compiled DLL checked into this repository. Neither built `tunnel.dll`
nor WireGuardNT native libraries are uploaded as workflow artifacts.

## Success condition and narrow interpretation

Passing compilation plus `NativeLibrary.GetExport(...,
"WireGuardTunnelService")` would prove we can build and dynamically inspect
the actual upstream embeddable DLL. It would **not** prove WireGuard
configuration, service SID, driver safety, handshake or fail-close.

An unsigned or source-built `tunnel.dll` must **never be installed on the
critical UU remote machine**. A separate authenticated build/signing and
provenance review is required before even considering deployment.

The Windows manager and status-only SCM lab from PR #9 are independent and
must remain nonmutating. No WireGuard service is activated here.

## Required gates before running an actual tunnel

- Provision an independent throwaway Windows VM with a snapshot and access
  to the hypervisor console if the VPN drops.
- Verify native DLL signatures, licenses, matching architecture and protected
  install/file ACLs.
- Separate isolated peer (new keys) and disposable WireGuard server, NOT the
  user's Windows peer or production Oracle VM.
- Prove SCM service start/stop and out-of-band rollback before enabling
  full IPv4+IPv6 routing or any WFP filter.
- Verify IPv4/IPv6/DNS leakage, reconnect, crash and complete UU P2P
  continuity separately; passing a source-build test is not protection.

No test in this PR changes the active WireSock connection or Oracle.
