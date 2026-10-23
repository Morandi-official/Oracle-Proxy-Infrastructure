using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.LabManager;

/// <summary>
/// Production-shaped, *non-operational* privileged control boundary.
/// Authentication is derived only from the impersonated Windows caller.
/// Neither command can start/stop a tunnel until OS WFP fail-closed
/// installation, verification, crash recovery and safe release exist.
/// </summary>
internal sealed class SafeControlGate
{
    internal const string PipeName = "OracleProxyLabManager.Control.v1";
    internal const string FixedProfile = "oracle-proxy-main";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly HashSet<Guid> _seen = new();
    private const int MaxSeen = 128;
    // The live SYSTEM pipe now uses the same transaction contract tested in R27.
    // Only the permanently denying adapter can be constructed here: neither
    // a client packet nor a CI lab build can inject a mutating backend.
    private readonly ProductionVpnCoordinator _coordinator =
        new(new UnavailableProductionKernel());

    private static string Reply(string code) => JsonSerializer.Serialize(new
    {
        schema_version = 1,
        ok = false,
        code,
        profile = FixedProfile,
        network_operation_performed = false,
        native_tunnel_control_enabled = false,
        actual_wfp_enforcement_verified = false,
        explicit_disconnect_committed = false
    });

    // The only supported operations are *requests*, never OS mutations.
    // Keep caller authorization supplied solely by RunAsClient in ServeAsync;
    // offline tests inject it and cannot authorize a live service.
    internal string Evaluate(string? payload, bool osVerifiedElevatedAdministrator)
    {
        if (!osVerifiedElevatedAdministrator)
            return Reply("ELEVATED_OS_ADMIN_REQUIRED");
        if (string.IsNullOrEmpty(payload) || Utf8.GetByteCount(payload) > 512)
            return Reply("INVALID_FRAME");

        Guid id;
        string? command;
        try
        {
            using var doc = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                MaxDepth = 3,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Reply("INVALID_FRAME");
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in root.EnumerateObject())
            {
                if (p.Name is not ("protocol_version" or "request_id" or "command" or "profile") ||
                    !keys.Add(p.Name))
                    return Reply("UNEXPECTED_OR_DUPLICATE_FIELD");
            }
            if (keys.Count != 4 ||
                root.GetProperty("protocol_version").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("protocol_version").TryGetInt32(out int ver) || ver != 1 ||
                root.GetProperty("request_id").ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(root.GetProperty("request_id").GetString(), "D", out id) ||
                id == Guid.Empty ||
                root.GetProperty("command").ValueKind != JsonValueKind.String ||
                root.GetProperty("profile").ValueKind != JsonValueKind.String)
                return Reply("INVALID_FRAME");
            command = root.GetProperty("command").GetString();
            if (root.GetProperty("profile").GetString() != FixedProfile)
                return Reply("PROFILE_NOT_ALLOWLISTED");
            if (command is not ("RequestConnect" or "RequestExplicitDisconnect"))
                return Reply("COMMAND_NOT_ALLOWLISTED");
        }
        catch (JsonException) { return Reply("INVALID_JSON"); }

        lock (_seen)
        {
            if (_seen.Contains(id)) return Reply("REPLAY_DENIED");
            if (_seen.Count >= MaxSeen) return Reply("REPLAY_CACHE_FULL");
            _seen.Add(id);
        }

        // Real OS token authentication is done by pipe impersonation above.
        // The wired production backend remains unavailable, so no RPC is
        // allowed to decrypt a key, launch a tunnel, change WFP or release it.
        // A disconnect must not be reported as committed on unknown startup.
        string code = command == "RequestConnect"
            ? _coordinator.Connect() : _coordinator.ExplicitDisconnect();
        return Reply(code);
    }

    private static NamedPipeServerStream CreateServer()
    {
        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 512, 512, acl);
    }

    internal async Task ServeAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            using var pipe = CreateServer();
            try
            {
                await pipe.WaitForConnectionAsync(token);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                deadline.CancelAfter(TimeSpan.FromSeconds(4));
                byte[] bytes = new byte[513];
                int length = 0;
                bool terminated = false;
                while (length < bytes.Length)
                {
                    int read = await pipe.ReadAsync(bytes.AsMemory(length, 1), deadline.Token);
                    if (read == 0) break;
                    if (bytes[length++] == (byte)'\n') { terminated = true; break; }
                }
                string? frame = terminated && length <= 513
                    ? Utf8.GetString(bytes, 0, length - 1).TrimEnd('\r') : null;

                bool elevatedAdmin = false;
                pipe.RunAsClient(() =>
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    // UAC-filtered (not elevated) admin tokens fail the check.
                    elevatedAdmin = identity.IsAuthenticated &&
                        new WindowsPrincipal(identity).IsInRole(
                            WindowsBuiltInRole.Administrator);
                });
                string reply = Evaluate(frame, elevatedAdmin);
                using var writer = new StreamWriter(pipe, Utf8, 512, true)
                { AutoFlush = true };
                await writer.WriteLineAsync(reply);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (Exception)
            {
                // Malformed, stalled or unprivileged client cannot crash SCM.
                // No request bytes, credentials or profile paths are logged.
            }
        }
    }
}
