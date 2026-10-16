namespace OracleProxy.LabManager;

internal static class NativeWfpFilterInventorySelfTests
{
    internal static bool Run()
    {
        try
        {
            var first = NativeWfpFilterInventory.Read();
            var second = NativeWfpFilterInventory.Read();
            if (!OperatingSystem.IsWindows() ||
                !first.IsReadOnlyOsObservation ||
                !second.IsReadOnlyOsObservation ||
                first.ReadableFilterCount is < 1 or > 8192 ||
                second.ReadableFilterCount is < 1 or > 8192 ||
                first.AllDeviceWfpVerified || second.AllDeviceWfpVerified ||
                first.AuthorizesTunnelOrRuleRelease ||
                second.AuthorizesTunnelOrRuleRelease ||
                default(NativeWfpFilterObservation).IsReadOnlyOsObservation)
                throw new InvalidOperationException("Real native BFE snapshot did not satisfy read-only contract");
            Console.WriteLine("R46_NATIVE_WFP_FILTER_ENUM_PASS: readable_count=" +
                first.ReadableFilterCount +
                " complete_observation=true all_device_verified=false release_authorized=false");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R46_NATIVE_WFP_FILTER_ENUM_FAIL");
            return false;
        }
    }
}
