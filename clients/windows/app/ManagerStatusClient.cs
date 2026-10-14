using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// This GUI consumes only an OS-authenticated read-only STATUS pipe. No
// Start/Stop/Enable/Disable, arbitrary file paths, secrets or network actions.
internal sealed record ManagerSnapshot(
    string Mode, bool StatusPipeAuthenticated, bool MutationsAvailable,
    string Connected, string LeakProtection, bool NativeDllLoaded);

internal static class ManagerStatusClient
{
    internal const string PipeName = "OracleProxyLabManager.Status.v1";
    internal const string UntrustedEndpointMessage = "后台服务身份不可验证";
    internal static async Task<ManagerSnapshot> ReadAsync(CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(2500, deadline.Token);
        // A named pipe DACL authenticates the CLIENT, not the SERVER.
        // Reject a user-created replacement pipe before sending a request or
        // consuming a forged status report. SCM PID binding is necessary but
        // NOT a substitute for future installer ACLs and Authenticode checks.
        if (!IsBoundToExpectedService(pipe))
            throw new InvalidOperationException(UntrustedEndpointMessage);

        // No self-asserted identity, address or executable path in request.
        var utf8 = new UTF8Encoding(false, true);
        using var writer = new StreamWriter(pipe, utf8, 512, leaveOpen: true) {
            AutoFlush = true
        };
        using var reader = new StreamReader(pipe, utf8, false, 512, leaveOpen: true);
        await writer.WriteLineAsync("{\"protocol_version\":1,\"command\":\"Status\"}");
        string response = await reader.ReadLineAsync().WaitAsync(
            TimeSpan.FromSeconds(3), deadline.Token)
            ?? throw new InvalidOperationException("后台服务无响应");
        if (Encoding.UTF8.GetByteCount(response) > 2048)
            throw new InvalidOperationException("后台服务响应长度不符合协议");

        using var doc = JsonDocument.Parse(response, new JsonDocumentOptions {
            MaxDepth = 4, AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow
        });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.GetProperty("ok").GetBoolean() ||
            root.GetProperty("code").GetString() != "STATUS_ONLY" ||
            root.GetProperty("schema_version").GetInt32() != 1 ||
            root.GetProperty("manager_mode").GetString() != "read_only_real_windows_service" ||
            !root.GetProperty("authenticated_status_pipe").GetBoolean() ||
            root.GetProperty("mutating_commands_available").GetBoolean())
            throw new InvalidOperationException("后台服务版本或权限边界不符合预期");

        string connection = root.GetProperty("wireguard_tunnel_connected").GetString() ?? "";
        string leak = root.GetProperty("leak_protection").GetString() ?? "";
        if (connection != "unverified" || leak != "unverified")
            throw new InvalidOperationException("该版本不支持验证实际 VPN 连接或防泄漏状态");

        return new ManagerSnapshot(
            "read_only_real_windows_service", true, false,
            connection, leak,
            root.GetProperty("native_dll_loaded").GetBoolean());
    }

    // The SCM exposes the current PID of the named own-process service;
    // compare it with Windows' PID for the ACTUAL connected pipe server.
    // No process ID or service name is accepted from pipe JSON.
    private static bool IsBoundToExpectedService(NamedPipeClientStream pipe)
    {
        if (!OperatingSystem.IsWindows() ||
            !GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid) ||
            serverPid == 0 || serverPid > int.MaxValue)
            return false;

        IntPtr scm = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (scm == IntPtr.Zero) return false;
        try
        {
            IntPtr service = OpenService(scm, "OracleProxyLabManager",
                0x0004); // SERVICE_QUERY_STATUS
            if (service == IntPtr.Zero) return false;
            try
            {
                if (!QueryServiceStatusEx(service, 0, out var status,
                    (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _))
                    return false;
                if (status.ProcessId != serverPid ||
                    (status.ServiceType & 0x10) == 0 || // SERVICE_WIN32_OWN_PROCESS
                    status.CurrentState != 4)          // SERVICE_RUNNING
                    return false;
                // Reject non-session-zero impostors even if SCM reports a PID.
                return Process.GetProcessById((int)serverPid).SessionId == 0;
            }
            finally { CloseServiceHandle(service); }
        }
        catch
        {
            // Lack of SCM/process query access fails closed.
            return false;
        }
        finally { CloseServiceHandle(scm); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service, int infoLevel, out ServiceStatusProcess status,
        uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

}
