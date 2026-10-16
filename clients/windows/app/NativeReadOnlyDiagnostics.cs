using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace OracleProxy.Windows.Preview;

// R54: no script interpreter, shell, network request, registry write,
// adapter mutation, route manipulation, driver installation or elevation.
// These are OS observations, NOT a WireGuard or WFP protection audit.
internal static class NativeReadOnlyDiagnostics
{
    [StructLayout(LayoutKind.Explicit, Size = 28, Pack = 4)]
    private struct SockaddrInet
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(4)] public uint Alignment;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Prefix
    {
        public SockaddrInet Address;
        public byte Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Route
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public Prefix DestinationPrefix;
        public SockaddrInet NextHop;
        public byte SitePrefixLength;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint Metric;
        public uint Protocol;
        public byte Loopback;
        public byte AutoconfigureAddress;
        public byte Publish;
        public byte Immortal;
        public uint Age;
        public uint Origin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RouteTable
    {
        public uint Count;
        public Route First;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint Flags;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpForwardTable2(ushort addressFamily, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr table);

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint rights);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint rights);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level,
        out ServiceStatus status, uint bufferSize, out uint sizeRequired);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    internal static bool NativeRouteLayoutMatches() =>
        IntPtr.Size == 8 &&
        Marshal.SizeOf<SockaddrInet>() == 28 &&
        Marshal.SizeOf<Prefix>() == 32 &&
        Marshal.OffsetOf<Route>(nameof(Route.InterfaceIndex)).ToInt32() == 8 &&
        Marshal.OffsetOf<Route>(nameof(Route.DestinationPrefix)).ToInt32() == 12 &&
        Marshal.OffsetOf<Route>(nameof(Route.NextHop)).ToInt32() == 44 &&
        Marshal.OffsetOf<Route>(nameof(Route.Origin)).ToInt32() == 100 &&
        Marshal.SizeOf<Route>() == 104 &&
        Marshal.OffsetOf<RouteTable>(nameof(RouteTable.First)).ToInt32() == 8;

    // Route count and interface membership are private to this process.
    // Never log addresses, gateway information or interface indices.
    private static bool HasDefaultRoute(AddressFamily family, HashSet<int> candidateIndices)
    {
        if (!NativeRouteLayoutMatches())
            throw new InvalidOperationException("本机 Windows 路由 API 布局无法确认。");
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (GetIpForwardTable2(checked((ushort)family), out buffer) != 0 ||
                buffer == IntPtr.Zero)
                throw new InvalidOperationException("Windows 路由数据暂不可用。");
            int count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > 8192)
                throw new InvalidOperationException("Windows 路由数量异常。");
            int offset = Marshal.OffsetOf<RouteTable>(nameof(RouteTable.First)).ToInt32();
            int stride = Marshal.SizeOf<Route>();
            bool found = false;
            for (int i = 0; i < count; ++i)
            {
                var row = Marshal.PtrToStructure<Route>(
                    IntPtr.Add(buffer, checked(offset + i * stride)));
                if (row.DestinationPrefix.Address.Family != (ushort)family)
                    throw new InvalidOperationException("Windows 路由格式无法验证。");
                if (row.DestinationPrefix.Length == 0 &&
                    row.InterfaceIndex is > 0 and <= int.MaxValue &&
                    candidateIndices.Contains((int)row.InterfaceIndex))
                    found = true;
            }
            return found;
        }
        finally
        {
            if (buffer != IntPtr.Zero) FreeMibTable(buffer);
        }
    }

    private static string ServiceState(IntPtr scm, string name)
    {
        IntPtr service = IntPtr.Zero;
        try
        {
            service = OpenService(scm, name, 0x0004); // SERVICE_QUERY_STATUS
            if (service == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == 1060 ? "Absent" : "Unknown";
            if (!QueryServiceStatusEx(service, 0, out ServiceStatus status,
                (uint)Marshal.SizeOf<ServiceStatus>(), out _))
                return "Unknown";
            return status.CurrentState switch
            {
                1 => "Stopped",
                2 => "StartPending",
                3 => "StopPending",
                4 => "Running",
                5 => "ContinuePending",
                6 => "PausePending",
                7 => "Paused",
                _ => "Unknown"
            };
        }
        finally
        {
            if (service != IntPtr.Zero) CloseServiceHandle(service);
        }
    }

    private static bool IsProcessPresent(string allowedName)
    {
        // Process names only; no PID, command line, executable path or token.
        Process[] processes = Process.GetProcessesByName(allowedName);
        try { return processes.Length > 0; }
        finally
        {
            foreach (var process in processes) process.Dispose();
        }
    }

    internal static DiagnosticSnapshot Collect()
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("该测试版仅支持 Windows。");

        var adapterCandidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                adapter.NetworkInterfaceType is NetworkInterfaceType.Ethernet or
                    NetworkInterfaceType.Wireless80211)
            .ToArray();
        var ipv4Indices = new HashSet<int>();
        var ipv6Indices = new HashSet<int>();
        foreach (var adapter in adapterCandidates)
        {
            IPInterfaceProperties properties = adapter.GetIPProperties();
            var v4 = properties.GetIPv4Properties();
            var v6 = properties.GetIPv6Properties();
            if (v4 is not null && v4.Index > 0) ipv4Indices.Add(v4.Index);
            if (v6 is not null && v6.Index > 0) ipv6Indices.Add(v6.Index);
        }

        bool v4Default = HasDefaultRoute(AddressFamily.InterNetwork, ipv4Indices);
        bool v6Default = HasDefaultRoute(AddressFamily.InterNetworkV6, ipv6Indices);

        IntPtr scm = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        string wiresockService, wireguardManager, wiresockDriver;
        try
        {
            wiresockService = scm == IntPtr.Zero ? "Unknown" :
                ServiceState(scm, "WireSockConnectService");
            wireguardManager = scm == IntPtr.Zero ? "Unknown" :
                ServiceState(scm, "WireGuardManager");
            wiresockDriver = scm == IntPtr.Zero ? "Unknown" :
                ServiceState(scm, "WireSock");
        }
        finally
        {
            if (scm != IntPtr.Zero) CloseServiceHandle(scm);
        }
        bool uu = IsProcessPresent("GameViewerServer");
        return new DiagnosticSnapshot(adapterCandidates.Length,
            v4Default, v6Default, wiresockDriver, wiresockService,
            wireguardManager, uu, DateTimeOffset.UtcNow.ToString("O"));
    }
}
