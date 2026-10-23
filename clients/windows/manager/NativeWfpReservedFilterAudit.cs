using System.Runtime.InteropServices;

namespace OracleProxy.LabManager;

// R45: native, read-only Base Filtering Engine lookup for reserved filter IDs.
// These filter keys have NOT been installed by this application. A returned
// object is NOT proof of full-device, authenticated or correctly ordered WFP.
internal readonly record struct NativeWfpReservedFilterSnapshot(
    bool EngineOpened,
    bool AllLookupsResolved,
    bool OwnedSublayerPresent,
    bool PhysicalIpv4FilterKeyPresent,
    bool PhysicalIpv6FilterKeyPresent,
    bool DnsIpv4FilterKeyPresent,
    bool DnsIpv6FilterKeyPresent)
{
    internal bool ActualDeviceLeakPreventionVerified => false;
    internal bool MayConnectTunnel => false;
    internal bool MayReleaseWfp => false;
}

internal static class NativeWfpReservedFilterAudit
{
    // Reserved and fixed for future signed provider/sublayer/filter review;
    // no Add/Delete or mutable WFP APIs are used by R45.
    private static readonly Guid Sublayer =
        new("93b4ee51-5e16-4e66-8de3-011e85b4e84a");
    private static readonly Guid PhysicalIpv4 =
        new("2f652742-8972-4a86-a64f-8a25f8f8c6c1");
    private static readonly Guid PhysicalIpv6 =
        new("5a672f2b-2ba5-4f45-a7e1-2ee283156d11");
    private static readonly Guid DnsIpv4 =
        new("b28b31da-a966-4d6c-b9b0-32f3aaea4c07");
    private static readonly Guid DnsIpv6 =
        new("7c272a37-c675-4d25-997c-f31976d2e21e");
    private const uint RpcCAuthnWinnt = 10;
    private const uint FwpFilterNotFound = 0x80320003;
    private const uint FwpSublayerNotFound = 0x80320007;

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0",
        CharSet = CharSet.Unicode)]
    private static extern uint Open(string? serverName,
        uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engine);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterGetByKey0")]
    private static extern uint GetFilter(IntPtr engine, ref Guid key,
        out IntPtr filter);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmSubLayerGetByKey0")]
    private static extern uint GetSublayer(IntPtr engine, ref Guid key,
        out IntPtr sublayer);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FreeMemory(ref IntPtr value);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint Close(IntPtr engine);

    private static bool Query(IntPtr engine, Guid fixedKey, bool sublayer,
        out bool present)
    {
        present = false;
        IntPtr value = IntPtr.Zero;
        try
        {
            uint status;
            if (sublayer)
                status = GetSublayer(engine, ref fixedKey, out value);
            else
                status = GetFilter(engine, ref fixedKey, out value);

            if (status == (sublayer ? FwpSublayerNotFound : FwpFilterNotFound))
                return value == IntPtr.Zero; // authoritative absence only
            if (status != 0 || value == IntPtr.Zero)
                return false; // denied/ambiguous -> fail the native query
            present = true;
            return true;
        }
        finally
        {
            if (value != IntPtr.Zero) FreeMemory(ref value);
        }
    }

    internal static NativeWfpReservedFilterSnapshot Read()
    {
        if (!OperatingSystem.IsWindows()) return default;
        IntPtr engine = IntPtr.Zero;
        try
        {
            if (Open(null, RpcCAuthnWinnt, IntPtr.Zero, IntPtr.Zero, out engine) != 0 ||
                engine == IntPtr.Zero)
                return default;
            bool q0 = Query(engine, Sublayer, true, out bool ownsSub);
            bool q1 = Query(engine, PhysicalIpv4, false, out bool v4);
            bool q2 = Query(engine, PhysicalIpv6, false, out bool v6);
            bool q3 = Query(engine, DnsIpv4, false, out bool dns4);
            bool q4 = Query(engine, DnsIpv6, false, out bool dns6);
            return new NativeWfpReservedFilterSnapshot(
                true, q0 && q1 && q2 && q3 && q4, ownsSub, v4, v6, dns4, dns6);
        }
        catch (Exception e) when (e is DllNotFoundException or
            EntryPointNotFoundException or BadImageFormatException or
            ExternalException or InvalidOperationException)
        {
            return default;
        }
        finally
        {
            if (engine != IntPtr.Zero) _ = Close(engine);
        }
    }
}
