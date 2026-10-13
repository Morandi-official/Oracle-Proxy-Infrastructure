# R2 — real Windows Filtering Platform (WFP) read-only BFE probe

This tiny Windows-native .NET program queries the actual
**Base Filtering Engine (BFE)** service's status and calls
`FwpmEngineOpen0` and `FwpmEngineClose0` in the real
`fwpuclnt.dll`. The normal WFP management engine is an OS boundary
that later filter enforcement code would need to interact with.

The probe only verifies that **the API opens and closes**, not that the
system filters traffic or that any kill switch is installed.

- It does **not** call `FwpmFilterAdd0`, `FwpmFilterDeleteById0`,
  `FwpmSubLayerAdd0`, `FwpmTransactionBegin0` or any WFP mutation.
- Does not restart BFE, disable IPv6, modify routes/DNS/firewall or create
  WireGuard adapters.
- Does not inspect, install, enumerate or enable **any** traffic filters.
- Does not query local user names, UU or WireSock process lists, credentials
  or network endpoints.
- Always returns `actual_ipv4_ipv6_dns_fail_closed_verified=false` and
  `uu_live_p2p_exception_verified=false`.

GitHub Windows CI executes this on a disposable cloud Windows runner and
compares Windows Firewall rule count and default route signatures
immediately before/after as a **regression smoke**, not as comprehensive
proof that no WFP filter changed. The source itself contains no mutation
APIs.

## Future safety prerequisites for active filter tests

1. Noncritical Windows VM with owner-operated hypervisor console and a
   demonstrated snapshot restore independent from any guest networking.
2. A separate, verifiable emergency rollback service for each filter
   and boot-time policy, including crashes/sleep/reboots.
3. Trusted fixed identities of UU client/helper processes, with signer
   verification and no broad physical leak exception.
4. OS-enforced IPv4 and IPv6 TCP/UDP/DNS denial of ordinary application
   physical egress while user VPN intent stays Enabled, even on crash.
5. Packet capture on the outside of the guest VM to detect physical leaks.
6. **Only after these:** verified live UU remote continuity. Do not run
   such experiments unattended on the user's UU-controlled Windows PC.

This is a read-only preflight, **not functional fail-close** or a VPN.
