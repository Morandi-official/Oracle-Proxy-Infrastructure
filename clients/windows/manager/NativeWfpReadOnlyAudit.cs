using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OracleProxy.LabManager;

// R35: actual Windows Filtering Platform native *read-only* inspection.
// Opening Base Filtering Engine (BFE) and looking up one reserved provider ID
// is NOT an audit of per-interface physical IPv4/IPv6, DNS, boot/crash or UU.
// In particular, a provider existing would never by itself authorize a VPN.
internal readonly record struct NativeWfpReadOnlySnapshot(
    bool LocalSystemSessionZero,
    bool BfeEngineOpened,
    bool ReservedProviderFound)
{
    internal bool FullDeviceFailClosedVerified => false;
    internal bool MayStartTunnel => false;
    internal bool MayReleaseFilter => false;
}

internal static class NativeWfpReadOnlyAudit
{
    // Reserved identity for a future reviewed, signed production WFP provider.
    // R35 DOES NOT create this provider or any filters.
    private static readonly Guid ReservedProviderKey =
        new("a943168e-c991-4b34-9215-a7c46094135b");
    private const uint RpcCAuthnWinnt = 10;

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0",
        CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName,
        uint authnService, IntPtr authIdentity, IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmProviderGetByKey0")]
    private static extern uint FwpmProviderGetByKey0(IntPtr engineHandle,
        ref Guid key, out IntPtr provider);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FwpmFreeMemory0(ref IntPtr pointer);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    internal static NativeWfpReadOnlySnapshot Read()
    {
        if (!OperatingSystem.IsWindows()) return default;
        bool system = false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            system = identity.IsSystem && Process.GetCurrentProcess().SessionId == 0;
        }
        catch { return default; }

        IntPtr engine = IntPtr.Zero, provider = IntPtr.Zero;
        try
        {
            if (FwpmEngineOpen0(null, RpcCAuthnWinnt, IntPtr.Zero,
                IntPtr.Zero, out engine) != 0 || engine == IntPtr.Zero)
                return new(system, false, false);

            // No enumerating third-party providers, no live rule changes.
            Guid key = ReservedProviderKey;
            bool found = FwpmProviderGetByKey0(engine, ref key, out provider) == 0 &&
                provider != IntPtr.Zero;
            return new(system, true, found);
        }
        catch (Exception ex) when (ex is DllNotFoundException or
            EntryPointNotFoundException or BadImageFormatException or
            ExternalException or InvalidOperationException)
        {
            return new(system, false, false);
        }
        finally
        {
            if (provider != IntPtr.Zero) FwpmFreeMemory0(ref provider);
            if (engine != IntPtr.Zero) _ = FwpmEngineClose0(engine);
        }
    }
}
