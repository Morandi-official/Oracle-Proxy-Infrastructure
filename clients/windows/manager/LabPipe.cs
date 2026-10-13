using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.LabManager;

/// <summary>
/// Actual local Windows named pipe and OS-token authorization (NOT a mock).
/// Remote clients cannot connect. Only Status is implemented. Even an
/// administrator cannot ask this service to run or stop WireGuard.
/// </summary>
internal static class LabPipe
{
    internal const string ProductionPipeName = "OracleProxyLabManager.Status.v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    private static NamedPipeServerStream CreateServer(string name, bool currentUserOnly)
    {
        if (currentUserOnly)
        {
            // Self-test only. This mode can never be reached via --manager-service.
            return new NamedPipeServerStream(name, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        }

        // Service mode: ACL grants ONLY LocalSystem and the local Administrators
        // group. A standard local account cannot connect even for Status.
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            512, 512, security);
    }

    internal static async Task RunServerAsync(string name, bool currentUserOnly,
        CancellationToken token, int maxConnections = int.MaxValue)
    {
        for (int i = 0; i < maxConnections && !token.IsCancellationRequested; i++)
        {
            using var pipe = CreateServer(name, currentUserOnly);
            await pipe.WaitForConnectionAsync(token);
            if (!pipe.IsConnected) continue;

            string reply;
            try
            {
                using var writer = new StreamWriter(pipe, Utf8, 512, true)
                {
                    AutoFlush = true
                };
                // Bound input BEFORE decoding/parsing; StreamReader.ReadLine
                // would otherwise buffer arbitrarily large client input.
                using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                readDeadline.CancelAfter(TimeSpan.FromSeconds(4));
                string? frame = await ReadBoundedFrameAsync(pipe, readDeadline.Token);

                // Verify identity through Windows impersonation; never trust
                // a SID, path, or permission claimed in JSON.
                string? callerSid = null;
                bool callerAllowed = false;
                pipe.RunAsClient(() =>
                {
                    using var id = WindowsIdentity.GetCurrent();
                    callerSid = id.User?.Value;
                    callerAllowed = id.IsSystem ||
                        new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                });
                if (currentUserOnly)
                {
                    // CI-only self-test trusts the *OS-verified* current SID,
                    // not a request property. Production never uses this path.
                    callerAllowed = callerSid ==
                        WindowsIdentity.GetCurrent().User?.Value;
                }

                reply = EvaluateFrame(frame, callerAllowed);
                await writer.WriteLineAsync(reply);
            }
            catch (Exception)
            {
                // Stop processing the single connection, no information leak.
                // The outer loop remains available for the next client.
                continue;
            }
        }
    }

    private static async Task<string?> ReadBoundedFrameAsync(
        Stream pipe, CancellationToken token)
    {
        byte[] buffer = new byte[513];
        int count = 0;
        while (count <= 512)
        {
            int length = await pipe.ReadAsync(buffer.AsMemory(count, 1), token);
            if (length == 0) return null;
            if (buffer[count] == (byte)'\n')
            {
                return Utf8.GetString(buffer, 0, count).TrimEnd('\r');
            }
            count++;
        }
        // Over-limit input is dropped without allocating further memory.
        return null;
    }

    internal static string EvaluateFrame(string? frame, bool osCallerAllowed)
    {
        if (!osCallerAllowed) return Response(false, "ACCESS_DENIED");
        if (string.IsNullOrEmpty(frame) || Utf8.GetByteCount(frame) > 512)
            return Response(false, "INVALID_SIZE");
        try
        {
            using var doc = JsonDocument.Parse(frame, new JsonDocumentOptions {
                MaxDepth = 3, AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Response(false, "INVALID_FRAME");
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in root.EnumerateObject())
            {
                if (field.Name is not ("protocol_version" or "command") ||
                    !keys.Add(field.Name))
                    return Response(false, "UNEXPECTED_OR_DUPLICATE_FIELD");
            }
            if (keys.Count != 2 ||
                root.GetProperty("protocol_version").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("protocol_version").TryGetInt32(out int ver) ||
                ver != 1 ||
                root.GetProperty("command").ValueKind != JsonValueKind.String)
                return Response(false, "INVALID_FRAME");

            if (root.GetProperty("command").GetString() != "Status")
                return Response(false, "MUTATION_DISABLED");

            return Response(true, "STATUS_ONLY");
        }
        catch (JsonException) { return Response(false, "INVALID_JSON"); }
    }

    private static string Response(bool ok, string code) =>
        JsonSerializer.Serialize(new {
            schema_version = 1,
            ok, code,
            manager_mode = "read_only_real_windows_service",
            wireguard_tunnel_connected = "unverified",
            leak_protection = "unverified",
            native_dll_loaded = false
        });

    internal static async Task<string> ClientRequestAsync(
        string pipeName, string message, CancellationToken token)
    {
        using var client = new NamedPipeClientStream(".", pipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        await client.ConnectAsync(3000, token);
        using var writer = new StreamWriter(client, Utf8, 512, true) { AutoFlush = true };
        using var reader = new StreamReader(client, Utf8, false, 512, true);
        await writer.WriteLineAsync(message);
        return (await reader.ReadLineAsync().WaitAsync(
            TimeSpan.FromSeconds(5), token)) ?? "";
    }
}
