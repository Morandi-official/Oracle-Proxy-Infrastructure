# Oracle Proxy Windows safe-alpha integration (NOT GA)

This branch integrates previously isolated engineering branches instead of
shipping an incomplete status-only preview as a VPN replacement.

Verified previously in separate ephemeral GitHub Actions environments:
- G12: genuine Windows native WireGuardNT encrypted IPv4 driver counters.
- G13: Linux kernel WireGuard across three network namespaces with IPv4,
  IPv6, synthetic UDP DNS A/AAAA, and a controlled intermediate outage.
- G14: native Windows GUI to OS-token authenticated admin IPC to SYSTEM
  manager to SCM tunnels and actual Winsock application UDP plus synthetic
  DNS receipt, with precisely scoped temporary CI firewall rules.
- R1/R2: DPAPI offline intent and actual Windows WFP BFE read-only probes.
- R3: explicit release blockers / negative evidence validation.
- G16: sanitized no-admin Windows 11 Home acceptance baseline.

The integration PR must demonstrate its OWN passing CI tests; evidence from
the source branches alone does not establish integration success. The main
branch and running production Oracle/WireSock/UU are not altered.

Remaining RELEASE-BLOCKING requirements: verified distinct Internet hosts,
production privileged manager with hardened authorized connect/disconnect,
anti-rollback intent, actual OS-enforced IPv4/IPv6/DNS fail-closed and
cold-boot/crash survival, UU exact-process direct routing and P2P continuity,
independent recovery/packet captures, signed installer/uninstaller/updater,
license review, key lifecycle, and approval for GA. **No v1.0.0 release.**

User's Windows 11 Home test PC remains READ_ONLY_ONLY until independent
recovery is demonstrated. Physical presence alone does not satisfy that.
