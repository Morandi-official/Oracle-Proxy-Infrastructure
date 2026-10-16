using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace OracleProxy.LabManager;

// R43: real, Windows-native IP Helper route table READ ONLY.
// Default route interface indexes are network observations, not proof that
// any WFP filter covers those indexes. No addresses or adapter names logged.
internal readonly record struct NativeRouteInventorySnapshot(
    bool IPv4QuerySucceeded,
    bool IPv6QuerySucceeded,
    IReadOnlyList<int>? IPv4DefaultRouteInterfaces,
    IReadOnlyList<int>? IPv6DefaultRouteInterfaces)
{
    internal bool QueriesSucceeded => IPv4QuerySucceeded && IPv6QuerySucceeded;
    internal bool CompleteWfpCoverageVerified => false;
    internal bool AuthorizesConnectionOrGuardRelease => false;
}

internal static class NativeRouteInventory
{
    // netioapi.h: SOCKADDR_INET union is 28 bytes and 4-byte aligned.
    // We deliberately model only its family field; the remaining bytes
    // are opaque. There is no private address parsing or logging here.
    [StructLayout(LayoutKind.Explicit, Size = 28, Pack = 4)]
    private struct SockaddrInet
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(4)] public uint FourByteAlignment;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IpAddressPrefix
    {
        public SockaddrInet Prefix;
        public byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RouteRow
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public IpAddressPrefix DestinationPrefix;
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
    private struct RouteTableHeader
    {
        public uint NumEntries;
        public RouteRow FirstRow;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpForwardTable2(ushort addressFamily, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr memory);

    // Validate ABI before touching any native row. Only x64 builds ship.
    internal static bool NativeLayoutExpected() =>
        IntPtr.Size == 8 &&
        Marshal.SizeOf<SockaddrInet>() == 28 &&
        Marshal.SizeOf<IpAddressPrefix>() == 32 &&
        Marshal.OffsetOf<RouteRow>(nameof(RouteRow.InterfaceIndex)).ToInt32() == 8 &&
        Marshal.OffsetOf<RouteRow>(nameof(RouteRow.DestinationPrefix)).ToInt32() == 12 &&
        Marshal.OffsetOf<RouteRow>(nameof(RouteRow.NextHop)).ToInt32() == 44 &&
        Marshal.OffsetOf<RouteRow>(nameof(RouteRow.Origin)).ToInt32() == 100 &&
        Marshal.SizeOf<RouteRow>() == 104 &&
        Marshal.OffsetOf<RouteTableHeader>(nameof(RouteTableHeader.FirstRow)).ToInt32() == 8;

    private static bool ReadFamily(AddressFamily family, out int[] interfaces)
    {
        interfaces = Array.Empty<int>();
        IntPtr table = IntPtr.Zero;
        if (!OperatingSystem.IsWindows() || !NativeLayoutExpected())
            return false;

        try
        {
            if (GetIpForwardTable2(checked((ushort)family), out table) != 0 ||
                table == IntPtr.Zero)
                return false;
            int count = Marshal.ReadInt32(table);
            // Refuse unusually large tables instead of pointer arithmetic
            // on an unchecked native count. Not a whole-network scanner.
            if (count < 0 || count > 8192) return false;
            int start = Marshal.OffsetOf<RouteTableHeader>(
                nameof(RouteTableHeader.FirstRow)).ToInt32();
            int stride = Marshal.SizeOf<RouteRow>();
            var found = new HashSet<int>();
            for (int i = 0; i < count; ++i)
            {
                IntPtr rowAddress = IntPtr.Add(table, checked(start + i * stride));
                RouteRow row = Marshal.PtrToStructure<RouteRow>(rowAddress);
                if (row.DestinationPrefix.Prefix.Family != (ushort)family)
                    return false;
                if (row.DestinationPrefix.PrefixLength != 0)
                    continue;
                if (row.InterfaceIndex is 0 or > int.MaxValue ||
                    !found.Add(checked((int)row.InterfaceIndex)) && found.Count > 64)
                    return false;
                if (found.Count > 64) return false;
            }
            interfaces = found.OrderBy(index => index).ToArray();
            return true;
        }
        catch (Exception e) when (e is DllNotFoundException or
            EntryPointNotFoundException or BadImageFormatException or
            OverflowException or ArgumentException or SEHException)
        {
            return false;
        }
        finally
        {
            if (table != IntPtr.Zero) FreeMibTable(table);
        }
    }

    internal static NativeRouteInventorySnapshot Read()
    {
        bool v4 = ReadFamily(AddressFamily.InterNetwork, out int[] ipv4);
        bool v6 = ReadFamily(AddressFamily.InterNetworkV6, out int[] ipv6);
        if (!v4 || !v6) return default;  // fail closed, no partial snapshot
        return new NativeRouteInventorySnapshot(v4, v6, ipv4, ipv6);
    }
}
