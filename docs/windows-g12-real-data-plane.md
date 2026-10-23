# G12: Real encrypted data, not just a WireGuard handshake

## Scope
This cloud-only test builds upon successful Windows G11 proof of a real
`GUI → Windows admin-only IPC → LocalSystem manager → upstream tunnel.dll
SCM services → signed WireGuardNT kernel adapter` chain.

On one disposable, Microsoft-hosted Windows GitHub Actions virtual machine,
the existing two narrow, independent localhost WireGuard peers have real
tunnel addresses `10.249.129.1/32` and `10.249.129.2/32`, allowed
routes only to each other, and WireGuard transport on
`127.0.0.1:52741/52742`. The G12 tool performs:
1. Wait for **both peers' genuine kernel-reported LastHandshake** values.
2. Query both peers' `TxBytes`/`RxBytes` via the **real signed WireGuardNT
   configuration API** (not a mocked C# health boolean).
3. Bind UDP sockets to each narrow tunnel interface and send small throwaway
   test packets in both directions.
4. Verify transmitted **and** received encrypted packet byte counters
   increase for both peers. This is evidence of real encrypted **IP payload
   forwarding** via WireGuard kernel interfaces, unlike keepalive/handshake
   timestamps alone.
5. Stop both services through the actual GUI/admin manager IPC and run
   independent emergency teardown, then inspect remaining adapters and
   default IPv4/IPv6 routes.

## Explicit exclusions
This does not verify application-level delivery: Windows Firewall might
discard UDP after decryption. Nor is it cross-host, cross-network, or
external Oracle. No real network-lock/WFP filters, proxy redirects, DNS
settings, default routes, UU/GameViewer applications, or private production
keys are involved. GitHub VM disposal is independent cleanup, not a
human-managed hypervisor snapshot.

Any real Internet data transfer test requires **an accessible independent
server under user control**. We will not silently change the existing
Oracle production WireGuard interface, UDP443 or UU system just to pass
this test.

## Security
The default end-user GUI from PR #17 excludes all CI-lab VPN controls
at compile time. Only this disposable CI workflow explicitly builds
`-p:EnableDisposableLabControls=true`. No executable containing live
privileged VPN control is published in a release artifact.

**Green G12 CI is a data-plane engineering milestone, not a GA release,
not external routing validation, and not a no-leak claim.**
