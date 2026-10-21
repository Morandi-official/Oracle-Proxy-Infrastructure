# Windows product delivery and acceptance gates

Updated 2026-10-21. Scope: Windows 10/11 x64 client and the Oracle administrator
console. Earlier WireGuardNT laboratory milestones are historical evidence;
the integrated product now embeds a source-built sing-box userspace
WireGuard/TUN core and the official signed Wintun driver.

## Evidence already obtained

Disposable GitHub Windows machines have exercised the real public executable,
SCM service, Windows identities, DPAPI and native WFP filters. Verified paths:

- Ordinary owner controls fixed service operations without daily UAC; a different
  ordinary Windows identity cannot use the pipe or decrypt SYSTEM state.
- Service-bound pipe rejects rogue servers, duplicate fields and arbitrary
  paths/commands. SYSTEM bundle extraction uses protected storage.
- Actual TUN/WireGuard TCP and fresh UDP DNS reach an isolated peer. Ordinary
  physical TCP and UDP DNS are blocked with protection enabled.
- Peer loss and core crash retain persistent protection. A dead or wrong-image
  core cannot authorize stale TUN permits. Explicit disconnect restores direct access.
- Missing encrypted state retains protection. Explicit UAC recovery preserves
  valid keys and commits OFF; failed service upgrades restore the previous image.
- Uninstall removes owned services, local keys, recovery backups and bundle cache.
- Official GameViewer 4.39.2.1561 and 4.41.1.2335 installers were statically
  inspected; valid NetEase identities and unsafe writable executable rejection
  were tested. This is not live UU continuity evidence.
- Administrator-issued account APIs, device limits, expiry, quotas, revocation,
  unified management, retained deletion accounting and server kernel enforcement
  have browser and disposable real-Linux lifecycle coverage.

## Acceptance bundle versus completed delivery

A main-branch acceptance bundle may be uploaded only after the isolated Windows
fault suite and the dedicated low-quota account's real Oracle acceptance pass.
The latter must show automatic device registration, Oracle public egress,
GUI-process loss, SCM crash recovery, account usage linkage and explicit
restoration of direct access. Missing test credentials are a failed prerequisite,
not a skipped success. Pull-request jobs do not receive production test credentials.

The binary allowlist is exactly OracleProxy.exe, OracleProxy.Core.exe and
OracleProxy.Guard.dll. Notices, hashes, Chinese recovery instructions, exact
revision/build metadata and corresponding build sources accompany the bundle.
The source archive includes actual vendored Go dependencies and generated build
pins. Private fixture and bad-upgrade executables are never distributed.

The application has no trusted publisher certificate. Candidate instructions and
metadata must say it is unsigned. Hash verification does not replace Authenticode.
The embedded Wintun bytes are separately compared against the official validly
signed upstream release.

## Outstanding requirements before completed delivery

| Requirement | Evidence still needed |
| --- | --- |
| Real Oracle end-to-end | Dedicated account secrets must reach the main job and every asserted stage must pass. |
| UU compatibility | Logged-in controller and controlled-device sessions must stay usable during connect, peer loss, core/service failure and reconnect. Current core direct outbound alone does not prove survival of core failure. No fixed user installation path is permitted. |
| Boot protection | Actual Windows restart and pre-login traffic behavior, durable connection intent and recovery on a locally recoverable computer. Same-boot filter inspection does not prove this. |
| IPv6 | Oracle VCN/VNIC, routing, forwarding and policy readiness plus real IPv6 transfer/leak tests. The current server descriptor blocks IPv6 and must not be described as dual-stack forwarding. |
| Update trust | Fixed payload hash checks and rollback are implemented; application publisher signing and a reviewed signed-update distribution mechanism remain outstanding. |
| Oracle allowance | Actual official API access and reviewed metric coverage/SKU units. Local counters or a denied query do not establish remaining monthly free allowance. |

Real UU and reboot tests require a computer with independent local recovery.
Cloud fixtures remain the preferred place for destructive and repeatable fault
coverage, but cannot establish an authenticated user's actual UU session.
Do not run unattended protection experiments on a computer accessible only by UU.

The Oracle backend is deployed through the explicitly authorized current-main
root bridge. Do not expose SSH credentials or a general command execution
interface in the web administrator console. Instance-principal usage collection
uses read-only IAM permissions and never exports its short-lived credentials.
