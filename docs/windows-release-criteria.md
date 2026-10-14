# Windows release gates — truthful alpha versus public product

Last reviewed: 2026-10-13. This document is deliberately a **blocking**
checklist rather than a declaration that the product is finished.

## Real engineering achievements already verified

- G7: official pinned-source embeddable WireGuard `tunnel.dll` loaded by
  custom Windows SCM host in disposable GitHub Windows VM. Two temporary
  localhost peers handshook with signed WireGuardNT 1.1.
- G11: **native GUI → Windows OS authenticated admin IPC → SYSTEM manager →
  native SCM tunnel services**, real two-sided handshake and stop/cleanup.
- Android A0: an Alpha debug APK has been built by GitHub CI, but not
  verified on a real device or reviewed for release permissions.
- Windows GUI preview: sanitized local diagnostics, no production tunnel.

Evidence: PR #12, #15 and GitHub Actions run 38390526504. The repository
has multiple stacked draft PRs and no production security sign-off.

## Must pass before calling Windows 1.0 GA

| Gate | Objective external proof | Status |
| --- | --- | --- |
| 1. Controlled publish | **Default binary contains no disposable CI lab control**, reproducible artifact allowlist and SHA-256 manifest | Under CI verification in this PR |
| 2. Provenance/legal | Review/ship all dependency license notices, distributable signed native DLL build, secure installer and code-signing certificates | BLOCKED |
| 3. Genuine nonproduction network | New separate peer, actual different-machine UDP handshake, packet forwarding across two machines, DNS and IPv4/IPv6 captures | BLOCKED: no independent publicly reachable lab Linux VM connected |
| 4. Production GUI control | Approved VPN profile import; no arbitrary service or shell commands; OS SID/signer-bound manager IPC, secret protection/DPAPI, durable ON/OFF intent, reproducible start/stop/reconnect | BLOCKED |
| 5. **Real** fail-close | OS-enforced WFP IPv4, IPv6, TCP, UDP and DNS fail-close that survives disconnect, app crash, reboot, before login; no reliance on simulated Boolean flags | BLOCKED |
| 6. UU uninterrupted | Verified exact UU executable identity and live UU UDP/P2P remote session, including failed tunnel and service restart, while other apps remain blocked | BLOCKED |
| 7. Independent recovery | On-site/bare-metal recovery for live host; cloud noncritical VM has out-of-band console/snapshot revert demonstrated **before** any persistent WFP test | BLOCKED |
| 8. Installer/updater | Signed installer/uninstaller/rollback that doesn't break WireSock or UU; no unintended route/WFP leftovers; update signature verification | BLOCKED |
| 9. Android GA | VpnService permissions, external server transfer, screen-off/reconnect, DNS/IPv6, on-device leak enforcement and signing/distribution tested | BLOCKED |
| 10. Server/backend | Separate documented and audited WireGuard server provisioning, key revocation/rotation, reliable sanitized management API, restricted access and rollback | BLOCKED |

## GA criteria

**All critical gates** must have independent logs/captures and security
review. A green CI build, two local peers shaking hands, or an unsigned
installer alone is not enough. We will not label any release that cannot
survive a real disconnect as "no leak".

## This PR's release-channel separation

By default, `EnableDisposableLabControls=false` and
`LabAdminControlClient.cs` is excluded **at compile time**.
Any `--ci-lab-start-a` / `--ci-lab-stop-a` CLI request returns exit 2
even if `GITHUB_ACTIONS` and `RUNNER_ENVIRONMENT` are forged.

Only tests that explicitly compile
`-p:EnableDisposableLabControls=true` include that interface. CI never
uploads that binary to an end-user artifact.

The downloadable preview is **read-only**, contains no native driver or
manager service and has explicit `READ_ME_FIRST.txt` and hash/manifest. It
is **unsigned** and not approved for critical UU-dependent remote hosts.

## Zero-cost strategy and limitations

- Keep all G11 lab work on disposable GitHub Windows virtual machines.
- Do not require a local hypervisor or new Oracle VM.
- Reuse production Oracle **only after** an explicit separately reviewed
  isolation/rollback proposal; do not modify its wg0, UDP443, WFP/iptables
  or live WireSock peer as a shortcut.
- Real UU packet-level coexistence needs actual UU software and an
  independently recoverable host; GitHub simulations cannot substitute it.
- No unattended real WFP changes on user's UU-dependent second PC.

The next product milestone after this gate is a securely packaged
**lab-only functional client**, followed by honest true fail-close and UU
acceptance; signed production GA comes last.
