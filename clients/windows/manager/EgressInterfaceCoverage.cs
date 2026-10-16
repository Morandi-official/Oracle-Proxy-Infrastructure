namespace OracleProxy.LabManager;

// R42: strict interface coverage contract for a FUTURE OS-backed SYSTEM kernel.
// A default route may switch interface after connect or while disconnecting.
// Never build this snapshot from caller JSON, the R40 privacy summary or
// self-reported VPN config. Production must independently query Windows route
// tables and actual installed WFP filter scope, including adapter churn.
internal readonly record struct EgressInterfaceCoverage(
    bool IndependentOsSnapshot,
    bool CurrentSessionSnapshot,
    bool AllUpInterfacesEnumerated,
    bool UnknownOrUnclassifiedEgressAbsent,
    bool AllInterfaceDnsProtected,
    IReadOnlyList<int>? Ipv4DefaultRouteInterfaceIndexes,
    IReadOnlyList<int>? Ipv6DefaultRouteInterfaceIndexes,
    IReadOnlyList<int>? GuardedIpv4InterfaceIndexes,
    IReadOnlyList<int>? GuardedIpv6InterfaceIndexes)
{
    private static bool RouteInterfacesCovered(
        IReadOnlyList<int>? defaults, IReadOnlyList<int>? guarded)
    {
        // Conservatively require both families. If IPv6 is disabled, an
        // independent IPv6 suppression proof is required in a future model.
        if (defaults is null || guarded is null ||
            defaults.Count is < 1 or > 64 || guarded.Count is < 1 or > 64)
            return false;
        var defaultSet = new HashSet<int>();
        var guardedSet = new HashSet<int>();
        foreach (int index in defaults)
            if (index <= 0 || !defaultSet.Add(index)) return false;
        foreach (int index in guarded)
            if (index <= 0 || !guardedSet.Add(index)) return false;
        return defaultSet.IsSubsetOf(guardedSet);
    }

    internal bool Verified =>
        IndependentOsSnapshot &&
        CurrentSessionSnapshot &&
        AllUpInterfacesEnumerated &&
        UnknownOrUnclassifiedEgressAbsent &&
        AllInterfaceDnsProtected &&
        RouteInterfacesCovered(Ipv4DefaultRouteInterfaceIndexes,
            GuardedIpv4InterfaceIndexes) &&
        RouteInterfacesCovered(Ipv6DefaultRouteInterfaceIndexes,
            GuardedIpv6InterfaceIndexes);
}
