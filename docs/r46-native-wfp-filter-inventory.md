# R46 — Real Windows Filtering Platform (WFP) filter enumeration

This adds OS-backed, *read-only* user-mode enumeration of WFP filter records
using Microsoft `fwpuclnt.dll` APIs:

- `FwpmEngineOpen0` and `FwpmFilterCreateEnumHandle0`
- Repeated bounded `FwpmFilterEnum0` pages (128 records per page, at most
  64 pages) with `FwpmFreeMemory0`
- `FwpmFilterDestroyEnumHandle0` and `FwpmEngineClose0`

The code checks returned pointer counts and frees allocations and handles.
It intentionally neither parses nor prints third-party filter metadata.
Windows CI checks this actual OS native call and verifies the unrelated
Windows Firewall rule inventory is unchanged. The actual SYSTEM SCM
manager also reads the inventory during its status-only startup.

**Critical limitations:** Microsoft documents that WFP enumeration reflects
only readable filters and the enumeration snapshot may become stale. The
number of readable filters is not evidence of our signed provider, filter
ownership, high-precedence per-interface IPv4/IPv6 block, DNS coverage,
boot persistence, multi-homing, endpoint/UU exception correctness or
packet-level fail-close. The snapshot's
`AllDeviceWfpVerified` and `AuthorizesTunnelOrRuleRelease` are
permanently false. No WFP policy is installed, edited or removed.

The R42 `EgressInterfaceCoverage` model still cannot be satisfied with
filter counts. Production `UnavailableProductionKernel` stays wired in,
and GA blocker #34 stays open. No user computer, Oracle, WireSock or
UU changes.

Reference API: Microsoft Win32 `FwpmFilterEnum0` and
`FwpmFilterCreateEnumHandle0` from fwpmu.h.
