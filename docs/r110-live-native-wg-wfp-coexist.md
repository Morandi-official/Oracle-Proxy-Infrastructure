# R110 — one real Windows CI: authenticated native WireGuardNT + nested OS WFP packet denial

## Objective

Integrate existing and already tested official Windows upstream pieces **on the same disposable Windows hosted CI runner**, rather than continuing to accumulate standalone disconnected proofs. The machine really runs official pinned upstream `tunnel.dll`, signature-checked official WireGuardNT 1.1, two distinct disposable native WireGuard SCM services, and the custom OS-authenticated GUI → SYSTEM manager. The existing native probes verify handshake, UDP payload and synthetic DNS over the lab peer adapters.

While both peers remain up, the R15 persistent **process-scoped** IPv4 TCP/443 guard stays installed. R110 then invokes the already reviewed R31 **all-application** Windows WFP-backed outbound block, narrowly restricted to fixed public DNS resolver test addresses 1.1.1.1/8.8.8.8 and corresponding IPv6 resolver IPs (no broad Internet, default gateway, UU or Windows routes). It requires an actual reachable IPv4 TCP/443 and UDP/53 baseline and independently observes subsequent Windows socket denial plus post-release recovery. When public IPv6 baseline exists, an IPv6 TCP denial is also tested, but no IPv6 baseline is **not** an IPv6 proof. It finally rechecks two native services and actual WireGuardNT handshake, then stops both via the GUI and removes only exact-owned firewall/test artifacts.

This is not merely an offline WFP Boolean simulation. It exercises **real Windows Firewall/WFP and actual official kernel tunnel services** in one OS epoch. It is still **NOT a complete user-installable full-device VPN or fail-closed kill switch**, and it does not justify a WireSock swap. Blocking four fixed resolver IPs is not equivalent to enforced all-destination egress across every physical interface. R110 does not install a production driver, edit Oracle's production wg0/NSG, use any production key, touch user's WireSock/UU, or run a reboot, crash, pre-login WFP, independent cross-host Internet peer, broad-system DNS/IP leak capture, or signed installer test.

## Exact execution and rollback controls

- Public repo, standard **free** GitHub `windows-latest`, same-repository exact `test/r110-native-wgnt-wfp-coexist-20261018` pull request only; in-script GITHUB_HEAD_REF, GITHUB_ACTIONS, RUNNER_ENVIRONMENT and exact newly owned SCM name checks. All generic/non-CI builds compile out the privileged Lab Manager and GUI entry points.
- Pin the upstream WireGuard Windows revision and WireGuardNT SDK binary hash, reject an invalid Authenticode signature and unprotected service config; no arbitrary destination/private key inputs or unsigned driver.
- A separate negative test proves that falsifying the runner environment cannot create the all-app WFP rule.
- Record original route/DNS/firewall context in runner-only secure scratch files; no network details or keys are uploaded.
- Create dynamic exact-owned R15 filter before peers; assert denial, then launch authenticated GUI/SYSTEM manager and two peers.
- Run R31 all-app fixed-destination deny/restore **while** peer services are live, with IPv4 TCP and UDP DNS real packet probes. Optional IPv6 TCP witness is clearly tagged if unavailable.
- Require pre- and post-tunnel OS rules and real probes, exact rule removal, real direct TCP/DNS restoration, native tunnel stop and original route/DNS/profile state. Failure denies CI. Disposable hosted runner is discarded at job end.
- ALWAYS-scoped cleanup steps remove only precisely named R15/R31 firewall rules and this CI's two native services/adapters/temporary keys; not unrelated Windows firewall rules or Oracle resources.

## Product staging

This moves engineering toward the user's suggested installable experimental test version, but the R83 `UnavailableProductionKernel` in the production service remains intentionally fail-closed and GA Issue #34 stays OPEN. A future installable full-device beta needs independent recovery before modifying real machine WFP; verified correct signed driver bundle and service ownership; all-target physical IPv4/IPv6 TCP/UDP/DNS leak checks, crash/disconnect/reboot/prelogin recovery; real Oracle fixed peer and independent packet proof; and actual UU remote session continuous while strict policies are applied. Tests that cannot run on the user's remote-critical machine must be proved in a safe externally recoverable Windows test environment instead.

## Expected evidence labels

The CI log distinguishes `R110_REAL_TWO_PEERS_AND_ALLAPP_OS_WFP_FIXED_DESTINATION_PASS` from `R110_FULL_DEVICE_DEFAULT_EGRESS_FAILCLOSE_AND_UU_NOT_TESTED`. The former requires genuine Windows native proofs but is **never** a claim of whole-device VPN safety or signed user release.
