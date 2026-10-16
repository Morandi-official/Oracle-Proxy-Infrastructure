namespace OracleProxy.LabManager;

// Invoked only as a nonmutating Windows command in disposable CI.
// It verifies the real native ABI/query result but cannot attest WFP coverage.
internal static class NativeRouteInventorySelfTests
{
    internal static bool Run()
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !NativeRouteInventory.NativeLayoutExpected())
                throw new InvalidOperationException("Native ABI not verified");
            var first = NativeRouteInventory.Read();
            var second = NativeRouteInventory.Read();
            if (!first.QueriesSucceeded || !second.QueriesSucceeded ||
                first.IPv4DefaultRouteInterfaces is null ||
                first.IPv6DefaultRouteInterfaces is null ||
                second.IPv4DefaultRouteInterfaces is null ||
                second.IPv6DefaultRouteInterfaces is null ||
                first.IPv4DefaultRouteInterfaces.Count is < 1 or > 64 ||
                first.IPv6DefaultRouteInterfaces.Count > 64 ||
                first.CompleteWfpCoverageVerified || second.CompleteWfpCoverageVerified ||
                first.AuthorizesConnectionOrGuardRelease ||
                second.AuthorizesConnectionOrGuardRelease ||
                default(NativeRouteInventorySnapshot).QueriesSucceeded)
                throw new InvalidOperationException("Native route status cannot attest protection");
            foreach (var indexes in new[]
                { first.IPv4DefaultRouteInterfaces, first.IPv6DefaultRouteInterfaces })
            {
                if (indexes.Any(index => index <= 0) ||
                    indexes.Count != indexes.Distinct().Count())
                    throw new InvalidOperationException("Invalid native route index");
            }
            // Counts only: do not log network interfaces, addresses, DNS, names,
            // remote-control identity or actual routes.
            Console.WriteLine("R43_NATIVE_ROUTE_INVENTORY_PASS " +
                "ipv4_defaults=" + first.IPv4DefaultRouteInterfaces.Count +
                " ipv6_defaults=" + first.IPv6DefaultRouteInterfaces.Count +
                " wfp_verified=false operations_enabled=false");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R43_NATIVE_ROUTE_INVENTORY_FAIL");
            return false;
        }
    }
}
