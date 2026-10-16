using System.Runtime.InteropServices;

namespace OracleProxy.LabManager;

// R46: actual Windows Filtering Platform read-only snapshot of readable
// filter records. BFE enumeration does NOT prove these filters are ours,
// persistent, ordered correctly, active across boot or block all devices.
internal readonly record struct NativeWfpFilterObservation(
    bool EngineOpened, bool EnumerationCompleted, int ReadableFilterCount)
{
    internal bool IsReadOnlyOsObservation => EngineOpened && EnumerationCompleted &&
        ReadableFilterCount >= 0;
    internal bool AllDeviceWfpVerified => false;
    internal bool AuthorizesTunnelOrRuleRelease => false;
}

internal static class NativeWfpFilterInventory
{
    // fwpmu.h user-mode API, not the similarly-named fwpmk.h kernel version.
    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", CharSet = CharSet.Unicode)]
    private static extern uint EngineOpen(string? serverName, uint authnService,
        IntPtr authIdentity, IntPtr session, out IntPtr engine);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterCreateEnumHandle0")]
    private static extern uint CreateEnumerator(IntPtr engine, IntPtr template,
        out IntPtr enumerator);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterEnum0")]
    private static extern uint EnumFilters(IntPtr engine, IntPtr enumerator,
        uint requested, out IntPtr entryPointers, out uint count);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDestroyEnumHandle0")]
    private static extern uint DestroyEnumerator(IntPtr engine, IntPtr enumerator);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FreeWfpMemory(ref IntPtr allocated);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint EngineClose(IntPtr engine);

    internal static NativeWfpFilterObservation Read()
    {
        if (!OperatingSystem.IsWindows()) return default;
        IntPtr engine = IntPtr.Zero, enumerator = IntPtr.Zero, entries = IntPtr.Zero;
        bool opened = false;
        int total = 0;
        try
        {
            if (EngineOpen(null, 10, IntPtr.Zero, IntPtr.Zero, out engine) != 0 ||
                engine == IntPtr.Zero)
                return default;
            opened = true;
            if (CreateEnumerator(engine, IntPtr.Zero, out enumerator) != 0 ||
                enumerator == IntPtr.Zero)
                return new(opened, false, 0);

            // Do not parse third-party filters or leak keys/names/conditions.
            // Bounded pages prevent runaway memory/CPU use on unexpected OS
            // configurations; exceeding the limit is "incomplete", never safe.
            const uint PageSize = 128;
            const int MaxPages = 64;
            for (int page = 0; page < MaxPages; ++page)
            {
                uint count;
                entries = IntPtr.Zero;
                if (EnumFilters(engine, enumerator, PageSize,
                        out entries, out count) != 0 ||
                    count > PageSize || (count != 0 && entries == IntPtr.Zero))
                    return new(opened, false, total);
                try
                {
                    for (int i = 0; i < checked((int)count); ++i)
                        if (Marshal.ReadIntPtr(entries, checked(i * IntPtr.Size)) ==
                            IntPtr.Zero)
                            return new(opened, false, total);
                    total = checked(total + (int)count);
                }
                finally
                {
                    if (entries != IntPtr.Zero)
                        FreeWfpMemory(ref entries);
                }
                if (count < PageSize)
                    return new(opened, true, total);
            }
            return new(opened, false, total); // potentially truncated
        }
        catch (Exception error) when (error is DllNotFoundException or
            EntryPointNotFoundException or BadImageFormatException or
            ExternalException or OverflowException or AccessViolationException)
        {
            return new(opened, false, total);
        }
        finally
        {
            if (entries != IntPtr.Zero) FreeWfpMemory(ref entries);
            if (enumerator != IntPtr.Zero && engine != IntPtr.Zero)
                _ = DestroyEnumerator(engine, enumerator);
            if (engine != IntPtr.Zero) _ = EngineClose(engine);
        }
    }
}
