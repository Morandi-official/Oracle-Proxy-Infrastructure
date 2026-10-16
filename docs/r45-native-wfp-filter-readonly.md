# R45 — native, read-only BFE filter/sublayer lookup

The actual LocalSystem SCM manager now calls `FwpmEngineOpen0`,
`FwpmSubLayerGetByKey0`, `FwpmFilterGetByKey0`, `FwpmFreeMemory0`
and `FwpmEngineClose0` from Windows `fwpuclnt.dll`.

Queries target one reserved, **currently uninstalled** app-specific
sublayer and four reserved filter GUIDs (IPv4/IPv6 egress and DNS).
The negative CI test on a disposable Windows runner must show those
objects **absent**, without performing any network mutation.

Unknown WFP HRESULTs or access-denied conditions fail the read-only
lookup instead of being interpreted as absence. Native resources are
freed on all exits. Only booleans/no identity are reported.

**This is not a kill switch**. Even if named objects are someday
present, GUID presence does not prove the provider is authenticated,
filters are correctly prioritized/conditioned, persist at boot, include
each physical interface or block DNS/TCP/UDP. The snapshot has
permanently false `ActualDeviceLeakPreventionVerified`,
`MayConnectTunnel` and `MayReleaseWfp`. R42/R43 route evidence
cannot override this result. Production `UnavailableProductionKernel`
remains the only installed backend, and release blocker #34 stays open.

No Oracle server, WireSock, UU, user network configuration or
production firewall changes were performed.
