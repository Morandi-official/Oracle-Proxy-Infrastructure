# R43: Windows-native IPv4/IPv6 route inventory (no network mutations)

## Implementation

`NativeRouteInventory` calls the Windows IP Helper APIs
`GetIpForwardTable2(AF_INET/AF_INET6)` and `FreeMibTable`, from the
*actual* default SYSTEM SCM service process at startup and from a CI
command. A native ABI guard checks the expected x64 layout of
`MIB_IPFORWARD_ROW2` before processing any route.

Each IPv4/IPv6 route with a zero-length destination prefix contributes
one **interface index** to the bounded, de-duplicated default-route
inventory. Repeated default routes for the same interface are valid.

The Windows manager-isolation CI exercises the native function and
independently compares **counts of distinct interface indexes** with the
Windows NetTCPIP `Get-NetRoute` cmdlet. Only aggregate counts and boolean
safety denial are logged, never IPs, gateways, interface indexes, MAC
addresses, keys or user identifiers. No PowerShell subprocess is used
inside the service. A native query failure causes its preflight to
fail; an absent IPv6 default route is a valid read-only observation and
does not imply all-device IPv6 is secure.

## Security limits

This is actual OS **route observation**, not enforcement. Enumeration
may become stale immediately due to route/adapter churn and cannot
establish what interface traffic truly used. Actual WFP provider/filter
ownership, filter priority, boot persistence, DNS interception and
third-party compatibility are NOT verified here.
`NativeRouteInventorySnapshot.CompleteWfpCoverageVerified` and
`AuthorizesConnectionOrGuardRelease` always remain false.

The default `UnavailableProductionKernel` is unchanged. R42's
`EgressInterfaceCoverage` remains a separate, stricter security contract:
never satisfy it from route counts alone. All tests are limited to
disposable Windows GitHub runners and perform no Oracle, WireSock, UU
or customer Windows networking changes. GA issue #34 remains OPEN.

Native layout references: Microsoft netioapi.h MIB_IPFORWARD_ROW2,
MIB_IPFORWARD_TABLE2 and GetIpForwardTable2 documentation.
