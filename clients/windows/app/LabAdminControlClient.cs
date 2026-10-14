using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// This GUI control channel is NEVER enabled on a normal Windows deployment.
// It exists solely for the GitHub-hosted disposable G7 lab. The receiving
// service enforces the actual OS admin token and fixed test service allowlist.
internal static class LabAdminControlClient
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal) {
        "StartLabPeerA", "StopLabPeerA", "StartLabPeerB", "StopLabPeerB",
        "InstallCiWfpGuard", "VerifyCiWfpGuard", "RemoveCiWfpGuard"
    };

    internal static bool OnDisposableRunner() =>
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
        Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted";

    internal static async Task<bool> SendAsync(string command, CancellationToken token)
    {
        if (!OnDisposableRunner() || !Allowed.Contains(command))
            return false;

        var message = JsonSerializer.Serialize(new {
            protocol_version = 1, request_id = Guid.NewGuid().ToString("D"),
            command
        });
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        using var pipe = new NamedPipeClientStream(".", "OracleProxyLabManager.AdminLab.v1",
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(3000, deadline.Token);
        var utf8 = new UTF8Encoding(false, true);
        using var writer = new StreamWriter(pipe, utf8, 512, true) {
            AutoFlush = true
        };
        using var reader = new StreamReader(pipe, utf8, false, 512, true);
        await writer.WriteLineAsync(message);
        var reply = await reader.ReadLineAsync().WaitAsync(
            TimeSpan.FromSeconds(5), deadline.Token);
        if (string.IsNullOrWhiteSpace(reply) ||
            Encoding.UTF8.GetByteCount(reply) > 2048) return false;
        using var doc = JsonDocument.Parse(reply);
        var root = doc.RootElement;
        return root.GetProperty("schema_version").GetInt32() == 1 &&
               root.GetProperty("scope").GetString() == "ephemeral_github_runner_only" &&
               !root.GetProperty("production_vpn_control").GetBoolean() &&
               !root.GetProperty("wfp_protection_verified").GetBoolean() &&
               root.GetProperty("ok").GetBoolean() &&
               root.GetProperty("code").GetString() == "LAB_SERVICE_CHANGED";
    }
}
