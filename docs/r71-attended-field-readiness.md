# R71 — physically attended narrow public-native acceptance: gate 0 (read-only preflight)

## Authorization boundary

The operator authorized **preparation and hosted CI** of R71. This does NOT authorize running code on a real Windows computer, attaching a real VNIC NSG, starting a temporary Oracle WireGuard service, or changing production Linux, Windows routes/DNS/WFP, WireSock or UU. Every future actual host mutation requires a separate documented operator confirmation with tested rollback and independent console recovery.

R68 has already established narrow real-public-host communication using the **official Windows WireGuard GUI**, followed by operator-attested Linux restoration. R69/R70 established CI-only genuine native Windows GUI -> LocalSystem WireGuardNT lab UDP/DNS plus OS narrow-route/DNS snapshots. No cross-host Windows **self-developed** native engine evidence exists.

## What this change delivers

A separate **unsigned, non-installer, non-VPN** executable at `clients/windows/r71-review` is published ONLY from a disposable GitHub Windows CI job. Its only accepted commands are `--self-test` (pure deny-by-default checks) and `--review-only` (local privacy-minimized OS observations). Default and arbitrary commands exit 2, before OS inspection. It never requires or requests elevation. It contains no client keys, server endpoint, WireGuard tunnel/driver, custom WFP policy, manager IPC or shell runner.

The report exposes only OS architecture, admin-token status, whether current session happens to match the active console session (NOT evidence that physical console recovery works), count of up Ethernet/Wi-Fi candidates, and running status for Windows Base Filtering Engine/Firewall services. No user/computer names, credentials, public/private IPs, adapter names/indices, physical addresses, gateway/DNS servers, UU process identities or other remote-control context is reported or uploaded.

Every dangerous evidence claim is hard-coded `false`: native-public Internet verification, IPv4/IPv6/DNS packet no-leak, WFP all-device, true out-of-band rescue, UU continuity, signed install/rollback, authorization for a native trial or production replacement. Successful `--review-only` exit code ONLY indicates that an OS observation was made.

CI compiles as self-contained one-file Windows x64 executable, asserts no native engine/manager bundled, refuses privileged CLI requests including a spoofed CI environment, runs pure self-tests and observations, checks all reported release blockers remain false, compares Windows default IPv4/IPv6 routes, DNS, adapters, firewall rule count and BFE/MpsSvc states before/after. A limited-retention **unsigned review-only** artifact plus an exact SHA-256 is retained for audit, NOT offered as a signed production installer.

## Actual R71 cross-public-host native acceptance is still blocked

1. There is NO reviewed test-mode production SYSTEM adapter for the project's own native WireGuardNT, pinned server identity, expiry/lease and OS-owned safe-Off. Current production gate remains `UnavailableProductionKernel`; lab control remains compile-time CI-only.
2. A fixed, temporary public peer must be freshly staged using new keys and an isolated server interface; previous R68 temporary keys, interface, firewall rules and VNIC NSG association were removed. No last-run peer configuration or real server identity is hardcoded or committed.
3. Exact Windows trial must keep the physical default routes and DNS unchanged, must refuse any widened AllowedIPs, must independently inventory remote-control transport and allow reliable physical recovery. UU being normal after R68 official-client test is NOT continuity proof for a native all-device WFP test.
4. If and only if those safety gates have independent evidence and the user grants **separate approval**, stage an attended, physically recoverable Windows native test with explicit time limit, preflight baseline, dry-run rollback and noncritical host. Do not install or enable a signed/unsigned native driver today.
5. Signed driver/installer, IPv4/IPv6/DNS external packet capture, WFP leak fail-close, reliable production explicit Off and long-lived UU verification remain necessary before functional Alpha or GA. GA blocker #34 remains OPEN.

## Review references

- R68: [manual official-client public path](r68-public-path-official-wireguard-manual-evidence.md)
- R69: [native config pre-activation CI](r69-native-route-profile-preactivation-audit.md)
- R70: [live native route and DNS CI](r70-native-active-route-dns-ci.md)
