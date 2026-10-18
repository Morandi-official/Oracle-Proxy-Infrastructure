# R107 engineering decision: reuse stable engine without skipping security testing

## Official WireGuard is the first-choice VPN dataplane

The official [WireGuard application embedding guide](https://www.wireguard.com/embedding/) recommends the Windows embeddable-dll-service instead of using WireGuardNT's lower-level API directly. The [wireguard-windows repository](https://github.com/WireGuard/wireguard-windows) is MIT-licensed. The [upstream enterprise administration guide](https://github.com/WireGuard/wireguard-windows/blob/master/docs/enterprise.md) documents service-based tunnel lifecycle and DPAPI-protected configuration.

Our source tree already contains native CI-lab WireGuard tunnel.dll/SCM host integration and verified Windows signed-engine preflights. Reuse these reviewed upstream components, not a novel hand-written cryptographic or tunnel kernel. Before any redistribution, audit the pinned exact version, upstream MIT notices, ABI, matching architecture, third-party WireGuardNT driver DLL Authenticode signer, DACL ownership, DLL search order and package supply-chain hash.

**Critical boundary:** the project's lab scripts and even real loopback WireGuard handshake do not prove its end-user GUI authorization, externally usable Oracle handshake, all-process IPv4/IPv6/DNS/UDP fail-close, safe disconnect, pre-login recovery or UU continuity. These remain independent acceptance gates and must not be silently skipped because an upstream component is reputable.

## WireSock SDK is not automatically open-source or reusable

WireSock has separately licensed SDK offerings. Its [published SDK EULA](https://www.wiresock.net/license/wiresock_sdk_eula) restricts reverse engineering/modification and unapproved redistribution; [the SDK product page](https://www.wiresock.net/wiresock-sdk) distinguishes noncommercial evaluation from commercial/OEM tiers. A downloadable client being free to use is not equivalent to an MIT-style source grant. Do not decompile, transplant proprietary driver code, embed its SDK, or distribute a WireSock binary as if it were open source without appropriate licensing. Publicly documented functionality may inform independently written compatibility tests.

## Staged deliverables

1. **R107 app-only test ZIP**: an independently reversible, ordinary-user SSH SOCKS5 proxy with a GUI and an owned local process. An intentionally limited useful test product, not a WireSock substitute.
2. **Full-VPN lab alpha**: upstream official signed WireGuard tunnel engine with fixed-profile authenticated manager, side-by-side with existing WireSock on disposable isolated Windows, with stop and rollback proof.
3. **Full-device fail-close & UU acceptance**: real WFP IPv4/IPv6 TCP/UDP/DNS, stale handshake, crash/reboot/pre-login, independent packet observation, and genuinely preserved UU remote session.
4. **GA**: secure signed installer/uninstaller/updater, user consent, externally recoverable real machines, independent signoff. R83 and GA Issue #34 remain blocked until objective evidence passes.

The user can accept a limited R107 app proxy without weakening any VPN production safety check. R107 packages no WireGuard or WireSock binaries.
