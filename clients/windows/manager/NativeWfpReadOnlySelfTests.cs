namespace OracleProxy.LabManager;

// R35 read-only OS probe: runs in ordinary CI and (via SCM) real SYSTEM.
internal static class NativeWfpReadOnlySelfTests
{
    internal static bool Run(bool expectSystem)
    {
        try
        {
            var before = NativeWfpReadOnlyAudit.Read();
            var after = NativeWfpReadOnlyAudit.Read();
            if (!OperatingSystem.IsWindows() ||
                !before.BfeEngineOpened || !after.BfeEngineOpened ||
                before.LocalSystemSessionZero != expectSystem ||
                after.LocalSystemSessionZero != expectSystem ||
                before.FullDeviceFailClosedVerified ||
                after.FullDeviceFailClosedVerified ||
                before.MayStartTunnel || after.MayStartTunnel ||
                before.MayReleaseFilter || after.MayReleaseFilter)
                throw new InvalidOperationException("Native BFE read-only invariant");
            Console.WriteLine("R35_NATIVE_BFE_READONLY_PASS: real WFP engine queried; " +
                "production network control and release remain denied");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R35_NATIVE_BFE_READONLY_FAIL");
            return false;
        }
    }
}
