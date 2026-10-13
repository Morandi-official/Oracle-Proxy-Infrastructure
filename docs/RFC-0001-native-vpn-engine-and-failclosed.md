# RFC-0001: Native VPN engines and controlled fail-closed architecture

**Status:** Proposal for design review (2026-10-13). **No deployment authorized.**
This describes a future self-developed client, not security provided by the
current WireSock configuration or by the W0/W1/W2 preview code.

## Existing verified constraints

- The Oracle VM already runs working WireGuard on UDP 51820. A persistent
  Oracle-side UDP 443 redirect to 51820 provides the currently tested path.
- The existing Windows WireSock `oracle-win2-udp443` profile was confirmed to
  exit from the Oracle public IPv4 address while connected.
- On the live Windows machine, enabling WireSock's network locks and manually
  disconnecting VPN caused the UU remote session to break. Locks are currently
  OFF. The live system is **not verified fail-closed**.
- The existing WireSock kernel interception does **not** expose a separate
  traditional VPN network adapter in the observed Windows adapter list.
- UU peer-to-peer traffic may use IPv6 UDP. Never globally disable IPv6 merely
  to simplify filtering.

## Product goal and critical distinction

| User-selected VPN intent | Tunnel state | Ordinary applications | Verified UU remote | Verified VPN transport |
| --- | --- | --- | --- | --- |
| Enabled | healthy & verified | tunnel only | direct on physical interface | approved Oracle endpoint only |
| Enabled | connecting | blocked, no direct fallback | direct | approved endpoint only |
| Enabled | stale handshake/failed | blocked, no direct fallback | direct | approved endpoint only |
| Enabled | unexpectedly disconnected/service crashed | blocked, no direct fallback | direct | approved endpoint only |
| Explicitly Disabled by user | any | ordinary direct access | direct | no transport required |

A process crash, driver error, reconnect attempt, Windows boot or VPN service
failure must never silently change persisted `Enabled` intent to `Disabled`.
Do not assert protection without observed packet-level IPv4/IPv6/DNS evidence.

## Windows engine decision

**Candidate:** official [WireGuard Windows embeddable DLL service](
https://github.com/WireGuard/wireguard-windows/tree/master/embeddable-dll-service)
with `tunnel.dll` + signed/verified compatible `wireguard.dll` and a
separate Windows service. This is the [official embedding recommendation](
https://www.wireguard.com/embedding/) instead of using low-level WireGuardNT
directly. Its C# demo and service APIs provide an integration starting point.

This is *not* the current WireSock API or a modified third-party installer.
In production the program should not activate the new engine concurrently
with WireSock or official WireGuard tunnel on the UU-dependent machine.

**License gate:** the WireGuard Windows repository declares MIT. WireGuardNT
source is GPLv2 while its official precompiled DLL downloads have separate
terms. Review and preserve the exact accompanying license files for the DLL
binary versions selected. Do not vendor or redistribute any driver or DLL
until version, digital signatures, hashes, licensing and update provenance
are validated. Do not implement bespoke WireGuard cryptography.

## Windows component boundaries

1. **Unprivileged UI (.NET WinForms):** user-selected intent and display only.
   UI Connected text is never treated as proof of tunnel safety.
2. **Privileged narrow control service:** install and manage a named tunnel,
   restrict accepted commands through authenticated local IPC/ACLs, protect
   locally generated private keys, maintain an audit log with no secrets.
   It MUST NOT accept arbitrary executable paths, endpoint strings or shell
   commands from an untrusted UI.
3. **WireGuard tunnel service:** exposes its independently verified interface
   identity; updates real handshake timestamps and traffic counters.
4. **WFP policy controller (future, separate module):** enforce at relevant
   outbound ALE v4/v6 layers with app and interface/endpoint predicates.
   Inbound UDP P2P, established-flow reauthorization, DNS, IPv6, QUIC and
   boot/reconnect behavior must all be tested.
5. **Independent recovery facility:** provide an on-site local administrator
   path to disable policy and roll back without depending on UU or Oracle SSH.

Policy state and WFP enforcement must persist across a control-service crash
when `Enabled` is persisted. The exact atomic transition ordering and
recovery mechanism are **unresolved design requirements**, not implemented
features. Neither process names nor UI labels are sufficient application
attestation. UU executable identity should be checked using trusted path,
signer, publisher, process token and intended service instances; test
unusual UU updates and P2P protocol changes.

WFP filter priority must not be approximated as a simple Windows Firewall
allow rule plus a blanket block; competing sublayers and block arbitration
require an explicit, isolated test design.

## Android engine decision

Use the official embeddable Android library
[`com.wireguard.android:tunnel`](https://www.wireguard.com/embedding/),
with the platform `VpnService` consent/permission flow. The Maven artifact
`1.0.20260102` presently advertises Apache-2.0 in its published metadata;
pin and re-verify exact versions, licenses and transitive components before
redistribution. Generate private keys on-device and never embed keys in
source or GitHub Actions.

Android `VpnService.Builder.addDisallowedApplication` supports excluding
specific installed packages from the VPN, using normal direct networking.
Always-on VPN / system "block connections without VPN" can change semantics,
so explicitly test app exclusions, reboot, process death, IPv6 and DNS on a
physical Android test phone before claiming any fail-closed behavior.
Android's application-exclusion mechanism is **not** interchangeable with
Windows WFP rules.

## Safety and release gates

- **G0 done:** independent read-only status collector and offline policy
  simulations pass in Windows PowerShell 5.1/7.
- **G1 preview built:** unsigned .NET Windows UI and headless diagnostics/policy
  checks run in a hosted Windows VM. This cannot establish tunnel functionality.
- **G2 next:** select exact upstream library versions and licenses; implement
  mocked service-control API with state/authorization tests; compile Windows
  x64 without installing real drivers.
- **G3:** isolated Windows disposable VM networking; test real handshake to an
  isolated peer (not the live UU host), endpoint fallback to UDP 443, interface,
  DNS and traffic accounting. Test engine/service crashes.
- **G4:** independent network-filter experiment on a lab computer, with
  physical/on-site recovery and tested rollback; prove UU P2P continuity,
  ordinary-app fail-closed on IPv4 and IPv6, DNS/UDP/TCP, boot, reconnect,
  sleep/wake, policy updates and actual traffic.
- **G5:** Android VpnService library integration, debug APK from CI, then
  actual-device permission, always-on/lockdown and offline tests.
- **G6:** code signing, installers and authenticated update policy; repository
  license decisions; full security review; opt-in staged deployment with
  local on-site recovery. Only here may the product be considered for the
  critical remote Windows host.

**Never silently deploy, replace working WireSock profiles, change Oracle VM
firewall or enable WFP blocking on the live UU-connected computer.**

## Authoritative specifications used

- WireGuard official: https://www.wireguard.com/embedding/
- WireGuard Windows embeddable DLL: https://github.com/WireGuard/wireguard-windows/tree/master/embeddable-dll-service
- WireGuardNT README and licensing: https://github.com/WireGuard/wireguard-nt
- Microsoft WFP ALE layers: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- Microsoft WFP ALE: https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-
- Microsoft WFP arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- Android VpnService builder: https://developer.android.com/reference/android/net/VpnService.Builder
- Android Maven tunnel POM: https://central.sonatype.com/artifact/com.wireguard.android/tunnel
