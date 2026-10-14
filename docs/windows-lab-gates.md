# Windows privileged service + official WireGuard DLL lab: evidence and gates

Status: **G4 development review**, not an authorization to change a user's PC.
This is a technical acceptance record for the isolated GitHub-hosted Windows VM.

## What is running in CI, and what is not

| Component | Actual implementation / test | Not yet established |
| --- | --- | --- |
| Manager | Independent .NET 8 **Windows Service** `OracleProxyLabManager`; temporarily registered as LocalSystem **manual start** in an ephemeral GitHub Windows runner; stopped/deleted in `finally` | Installer suitable for production, protected persisted VPN intent, crash-safe WFP |
| Authentication | Real Windows named pipe ACL allows only LocalSystem/Administrators; server calls `RunAsClient` and checks an OS-issued identity token, not user-supplied SID | Authenticated *mutating* API, protection from all local admin compromise, identity of signed caller binaries |
| Commands | Strict, bounded `Status` command; rejects `EnableVpn`, `DisableVpn`, `Connect`, `RunShell`, or additional JSON keys | Deliberate VPN control; no privileged tunnel control IPC implemented |
| Official `wireguard.dll` | CI downloads **actual** WireGuardNT 1.1 SDK from official HTTPS source, validates Authenticode and SHA-256, loads the native library and resolves exports. **No API invocation**, device creation or driver load. | Signed `tunnel.dll`, real tunnel SCM launch, handshake, peer provisioning |
| Embeddable `tunnel.dll` | Native exported `WireGuardTunnelService` P/Invoke bridge compiles, but is gated behind SYSTEM+Session0, protected paths, pins and preflight | Actual upstream `tunnel.dll` binary obtained/audited and export invoked in an isolated lab |
| Config & native files | Immutable-hash manifest, fixed config path; Windows NTFS ACL **read-only audit**, checks owner, inheritance, untrusted read on secret and untrusted write on DLLs and parent dirs. Negative tests use fake config bytes. | Protected installer/provisioner, real key management/DPAPI, proof against TOCTOU/symlink attacks |
| WFP + UU | None | **Actual IPv4/IPv6/DNS no-leak enforcement**, UU UDP P2P allow-list, reboot recovery |

## Upstream source provenance

Official repositories and interfaces:
- Embedding guide: https://www.wireguard.com/embedding/
- Embeddable service specification: https://github.com/WireGuard/wireguard-windows/blob/master/embeddable-dll-service/README.md
- Pin for further review of a reproducible source build: `WireGuard/wireguard-windows@6ece77bc487c8aa697e3c092197621c4f3e5ccb8`. This is **a source commit reference**, not a verified signed binary build.
- Official WireGuardNT SDK v1.1: https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip
- Archive SHA-256: `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace`
- Extracted AMD64 `wireguard.dll` SHA-256: `b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`
- GitHub-hosted Windows reported the DLL's Authenticode status `Valid`, and successfully loaded the module and resolved `WireGuardOpenAdapter`, `WireGuardCloseAdapter` and `WireGuardGetRunningDriverVersion` **without invoking them**.
- The upstream SDK includes a `LICENSE.txt`. Redistribution of any dependency requires separate license/notice review; **do not copy signed DLLs into this repository or GitHub release artifacts yet**.

The SHA-256 pins identify the tested archive and library but do not by themselves prove licensing, supply-chain integrity or safety of a future `tunnel.dll` build.

## Separate lab configuration safeguards

The future **fixed** configuration path is
`%ProgramData%\OracleProxyLab\config\lab-only.conf`. No other path is
accepted by the native host. The source tree or ZIP release MUST NOT include
any live WireGuard key, peer configuration or secret.

Before any real service activation on a disposable lab machine, require:
1. Lab VM with snapshot and independent hypervisor/console access; not the
   UU-controlled Windows machine and not the production Oracle peer.
2. Controlled installer **owned by Administrators/SYSTEM** with protected DACL
   and no weak writable inherited ACL on DLLs, manifest or config parents.
3. Config file not readable by nontrusted SIDs. A hash file kept alongside the
   DLL is NOT sufficient to stop an administrator or attacker who can modify both.
4. Verify the exact signed upstream driver module and review/compile the
   pinned embeddable DLL source; preserve upstream license/notice and build
   hashes. No uncontrolled "download latest" at runtime.
5. Generate a **separate lab private key** (never reuse a Windows production
   key) and an isolated peer. Verify endpoint and DNS without production SSH.
6. Prove **recovery first** before enabling any network interception.

The current code does not guarantee protection against filesystem TOCTOU,
all ancestor reparse points, hostile local administrators or unsigned
`tunnel.dll`. Hence production activation remains intentionally blocked.

## Independently recoverable lab sequence (future, not executed)

- Isolated VM snapshot/restore is the **primary out-of-band recovery**. Prove
  recovery can be invoked without in-guest VPN connectivity and without UU.
- First install/run only the status-only manager (no WireGuard service, no WFP).
  Test SCM start/status/stop/delete and clean reboots.
- Then install the audited upstream WireGuard tunnel service in the lab, **manual
  start only**, with required `WireGuardTunnel$...` name, `Nsi`/`TcpIp`
  dependencies, and `SERVICE_SID_TYPE_UNRESTRICTED` per upstream.
  Verify real handshake and interface/driver lifecycle on a distinct peer.
- Only after that, construct a *separate* WFP filter test on another
  disposable VM. Design atomic policy state persistence, on-site rollback,
  explicit UU exemptions, IPv4+IPv6+DNS leakage tests, and service-crash/
  reboot/sleep/restore cases **before enabling any real block**.
- Any failed lab experiment: use hypervisor console to shut down/revert
  the VM. SCM stop/delete is not a guaranteed WFP rollback if independent
  persistent filters have been installed. A WFP recovery controller is
  still required and has NOT been implemented.

## Prohibited on the UU remote PC

No `sc create`, `sc delete`, installer, driver registration, WFP changes,
network adapter changes, IPv6 disablement, WireSock Network Lock toggles,
VPN Disconnect, Oracle firewall change or machine reboot without a **separate
explicit user decision, out-of-band console recovery and safe runbook**.

**Passing CI is a software test result, not confirmation of no IP leaks.**
