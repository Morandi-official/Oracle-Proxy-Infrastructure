using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;

namespace OracleProxy.WfpReadOnly;

// Windows Filtering Platform Base Filtering Engine (BFE) is the underlying
// OS facility. This application does not call FwpmFilterAdd/Delete, open a
// write transaction, configure a sublayer, or alter firewall/routes/DNS.
internal static class WfpReadOnly
{
    private const uint RpcAuthWinNt = 10; // RPC_C_AUTHN_WINNT

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode,
        EntryPoint = "FwpmEngineOpen0")]
    private static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    internal sealed record ProbeResult(
        int schema_version,
        string mode,
        bool bfe_service_running,
        bool wfp_engine_opened,
        bool wfp_engine_closed,
        bool mutating_wfp_calls_performed,
        bool firewall_rules_modified,
        bool actual_ipv4_ipv6_dns_fail_closed_verified,
        bool uu_live_p2p_exception_verified);

    internal static ProbeResult Query()
    {
        bool bfe = false;
        bool opened = false;
        bool closed = false;
        if (OperatingSystem.IsWindows())
        {
            try {
                using var service = new ServiceController("BFE");
                bfe = service.Status == ServiceControllerStatus.Running;
                IntPtr handle = IntPtr.Zero;
                uint result = FwpmEngineOpen0(null, RpcAuthWinNt,
                    IntPtr.Zero, IntPtr.Zero, out handle);
                if (result == 0 && handle != IntPtr.Zero)
                {
                    opened = true;
                    try {
                        // An open BFE handle is NOT proof of a functioning
                        // fail-closed policy; no filters are inspected or set.
                    }
                    finally {
                        closed = FwpmEngineClose0(handle) == 0;
                    }
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or
                System.ComponentModel.Win32Exception or DllNotFoundException or
                EntryPointNotFoundException or UnauthorizedAccessException)
            {
                // Read-only errors must be sanitized: no machine/user paths.
            }
        }
        return new ProbeResult(1, "read_only_bfe_api", bfe, opened, closed,
            false, false, false, false);
    }

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1 ||
            args[0] is not ("--probe-json" or "--self-test"))
            return 3;
        ProbeResult snapshot = Query();
        Console.WriteLine(JsonSerializer.Serialize(snapshot));
        if (args[0] == "--probe-json") return 0;
        return snapshot.bfe_service_running && snapshot.wfp_engine_opened &&
               snapshot.wfp_engine_closed && !snapshot.mutating_wfp_calls_performed &&
               !snapshot.firewall_rules_modified &&
               !snapshot.actual_ipv4_ipv6_dns_fail_closed_verified &&
               !snapshot.uu_live_p2p_exception_verified ? 0 : 1;
    }
}
