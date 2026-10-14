using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace OracleProxy.WireGuardHost;

// Actual Windows SCM read-only API, fixed service name, no elevation.
// Status is a service-state observation, NOT a WireGuard handshake, route
// verification, security proof or an authorization for traffic.
internal static class LabServiceStatus
{
    internal const string ServiceName = "WireGuardTunnel$OracleProxyLab";

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private const uint SC_STATUS_PROCESS_INFO = 0;

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr scm, string name, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service, uint infoLevel, IntPtr buffer, uint bufferSize,
        out uint neededBytes);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    internal static string ReadOnlyStatus()
    {
        if (!OperatingSystem.IsWindows()) return "unsupported";
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return "unavailable";
        try
        {
            IntPtr service = OpenService(scm, ServiceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST
                    ? "absent" : "unavailable";
            try
            {
                int bytes = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                IntPtr buffer = Marshal.AllocHGlobal(bytes);
                try
                {
                    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, buffer,
                            (uint)bytes, out _))
                        return "unavailable";
                    var status = Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buffer);
                    return status.CurrentState switch
                    {
                        1 => "stopped",
                        2 => "start_pending",
                        3 => "stop_pending",
                        4 => "running",
                        5 => "continue_pending",
                        6 => "pause_pending",
                        7 => "paused",
                        _ => "unknown"
                    };
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { _ = CloseServiceHandle(service); }
        }
        finally { _ = CloseServiceHandle(scm); }
    }

    internal static string SanitizedJson() =>
        JsonSerializer.Serialize(new
        {
            schema_version = 1,
            service_name = ServiceName,
            service_status = ReadOnlyStatus(),
            tunnel_handshake_verified = false,
            actual_fail_closed_verified = false,
            query_mode = "read_only_scm"
        });
}
