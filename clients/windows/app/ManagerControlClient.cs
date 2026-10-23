using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// This is a NEGATIVE control-protocol probe, not a working VPN switch.
// A GUI action can only request the fixed profile; the SYSTEM manager
// checks the caller's OS admin token and refuses OS changes until WFP exists.
internal static class ManagerControlClient
{
    private const string PipeName = "OracleProxyLabManager.Control.v1";
    private const string FixedProfile = "oracle-proxy-main";

    internal static async Task<bool> VerifySafetyDenialAsync(
        string command, CancellationToken token)
    {
        if (command is not ("RequestConnect" or "RequestExplicitDisconnect"))
            return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        using var pipe = new NamedPipeClientStream(
            ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(3000, deadline.Token);
        if (!ManagerStatusClient.IsBoundToExpectedService(pipe))
            return false;
        var payload = JsonSerializer.Serialize(new
        {
            protocol_version = 1,
            request_id = Guid.NewGuid().ToString("D"),
            command,
            profile = FixedProfile
        });
        var utf8 = new UTF8Encoding(false, true);
        using var writer = new StreamWriter(pipe, utf8, 512, true)
        { AutoFlush = true };
        using var reader = new StreamReader(pipe, utf8, false, 512, true);
        await writer.WriteLineAsync(payload);
        string? response = await reader.ReadLineAsync().WaitAsync(
            TimeSpan.FromSeconds(4), deadline.Token);
        if (string.IsNullOrEmpty(response) ||
            utf8.GetByteCount(response) > 1024) return false;
        using var doc = JsonDocument.Parse(response, new JsonDocumentOptions
        {
            MaxDepth = 3,
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow
        });
        var root = doc.RootElement;
        return root.ValueKind == JsonValueKind.Object &&
            root.GetProperty("schema_version").GetInt32() == 1 &&
            root.GetProperty("ok").ValueKind == JsonValueKind.False &&
            root.GetProperty("code").GetString() == (command == "RequestConnect"
                ? "WFP_FAIL_CLOSED_NOT_IMPLEMENTED"
                : "DISCONNECT_REQUIRES_RECOVERY") &&
            root.GetProperty("profile").GetString() == FixedProfile &&
            !root.GetProperty("network_operation_performed").GetBoolean() &&
            !root.GetProperty("native_tunnel_control_enabled").GetBoolean() &&
            !root.GetProperty("actual_wfp_enforcement_verified").GetBoolean() &&
            !root.GetProperty("explicit_disconnect_committed").GetBoolean();
    }
}
