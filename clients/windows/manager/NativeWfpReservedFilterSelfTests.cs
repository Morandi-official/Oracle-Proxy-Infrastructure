namespace OracleProxy.LabManager;

// Actual Windows BFE queries, no provider/filter installation.
internal static class NativeWfpReservedFilterSelfTests
{
    internal static bool Run()
    {
        try
        {
            var first = NativeWfpReservedFilterAudit.Read();
            var second = NativeWfpReservedFilterAudit.Read();
            if (!first.EngineOpened || !first.AllLookupsResolved ||
                !second.EngineOpened || !second.AllLookupsResolved ||
                first.OwnedSublayerPresent || first.PhysicalIpv4FilterKeyPresent ||
                first.PhysicalIpv6FilterKeyPresent ||
                first.DnsIpv4FilterKeyPresent || first.DnsIpv6FilterKeyPresent ||
                first.ActualDeviceLeakPreventionVerified ||
                second.ActualDeviceLeakPreventionVerified ||
                first.MayConnectTunnel || second.MayConnectTunnel ||
                first.MayReleaseWfp || second.MayReleaseWfp)
                throw new InvalidOperationException("R45 reserved native WFP objects unavailable or ambiguous");
            Console.WriteLine("R45_NATIVE_WFP_FILTER_AUDIT_PASS: real BFE filter/sublayer keys absent; no device failclose or VPN permission");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R45_NATIVE_WFP_FILTER_AUDIT_FAIL");
            return false;
        }
    }
}
