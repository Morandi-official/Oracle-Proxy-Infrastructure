using System.IO.Pipes;
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
    private const string PipeName = "OracleProxyLabManager.Status.v1";
    internal static async Task<ManagerSnapshot> ReadAsync(CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(2500, deadline.Token);

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
}
