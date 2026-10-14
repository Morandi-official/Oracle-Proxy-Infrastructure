using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;

namespace OracleProxy.LabManager;

// Separate high-trust named pipe. This can control ONLY disposable lab
// services, and ONLY when explicitly enabled under a GitHub-hosted runner.
// Never allowed in the default production/service startup mode.
internal enum LabControlAction { StartA, StopA, StartB, StopB }

internal sealed class AdminLabControl
{
    internal const string PipeName = "OracleProxyLabManager.AdminLab.v1";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly HashSet<Guid> _seen = new();
    private const int MaxRequests = 256;

    // The short-lived SCM process does not inherit GitHub runner's job-level
    // environment. A separately staged marker under an admin-owned lab-only
    // directory is therefore also required for SYSTEM/Session0 activation.
    // This marker is a lab safety tripwire, NOT an attestation or permission.
    internal static bool IsDisposableCiLab()
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted")
            return true;
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            if (!id.IsSystem || System.Diagnostics.Process.GetCurrentProcess().SessionId != 0)
                return false;
            string root = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData), "OracleProxyLab");
            string marker = Path.Combine(root, ".ci-control-approved");
            return Directory.Exists(root) && File.Exists(marker) &&
                (File.GetAttributes(marker) & FileAttributes.ReparsePoint) == 0 &&
                File.ReadAllText(marker).Trim() == "DISPOSABLE_GITHUB_RUNNER_ONLY";
        }
        catch { return false; }
    }

    internal static bool ApplyToCiLabService(LabControlAction action)
    {
        if (!IsDisposableCiLab()) return false;
        string profile = action is LabControlAction.StartA or LabControlAction.StopA
            ? "lab-peer-a" : "lab-peer-b";
        string root = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData), "OracleProxyLab");
        if (!Directory.Exists(Path.Combine(root, profile))) return false;

        string service = "WireGuardTunnel$" + profile;
        using var controller = new ServiceController(service);
        try
        {
            if (action is LabControlAction.StartA or LabControlAction.StartB)
            {
                if (controller.Status == ServiceControllerStatus.Stopped)
                {
                    controller.Start();
                    controller.WaitForStatus(ServiceControllerStatus.Running,
                        TimeSpan.FromSeconds(20));
                }
                return controller.Status == ServiceControllerStatus.Running;
            }

            if (controller.Status != ServiceControllerStatus.Stopped)
            {
                controller.Stop();
                controller.WaitForStatus(ServiceControllerStatus.Stopped,
                    TimeSpan.FromSeconds(20));
            }
            return controller.Status == ServiceControllerStatus.Stopped;
        }
        catch
        {
            // Never expose Windows errors, process IDs or profile file paths.
            return false;
        }
    }

    internal string Process(string? payload, bool verifiedAdministrator,
                            bool disposableLabEnabled,
                            Func<LabControlAction, bool> dispatch)
    {
        string Reply(bool ok, string code) => JsonSerializer.Serialize(new {
            schema_version = 1, ok, code,
            scope = "ephemeral_github_runner_only",
            production_vpn_control = false,
            wfp_protection_verified = false
        });

        if (!verifiedAdministrator) return Reply(false, "ADMIN_OS_TOKEN_REQUIRED");
        if (!disposableLabEnabled) return Reply(false, "ISOLATED_LAB_GATE_CLOSED");
        if (string.IsNullOrEmpty(payload) || Utf8.GetByteCount(payload) > 512)
            return Reply(false, "INVALID_FRAME");

        Guid id;
        LabControlAction action;
        try
        {
            using var doc = JsonDocument.Parse(payload, new JsonDocumentOptions {
                MaxDepth = 3, AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Reply(false, "INVALID_FRAME");
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in root.EnumerateObject())
            {
                if (p.Name is not ("protocol_version" or "request_id" or "command") ||
                    !keys.Add(p.Name))
                    return Reply(false, "UNEXPECTED_FIELD");
            }
            if (keys.Count != 3 ||
                root.GetProperty("protocol_version").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("protocol_version").TryGetInt32(out int ver) || ver != 1 ||
                root.GetProperty("request_id").ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(root.GetProperty("request_id").GetString(), "D", out id) ||
                id == Guid.Empty ||
                root.GetProperty("command").ValueKind != JsonValueKind.String)
                return Reply(false, "INVALID_FRAME");

            action = root.GetProperty("command").GetString() switch
            {
                "StartLabPeerA" => LabControlAction.StartA,
                "StopLabPeerA" => LabControlAction.StopA,
                "StartLabPeerB" => LabControlAction.StartB,
                "StopLabPeerB" => LabControlAction.StopB,
                _ => (LabControlAction)(-1)
            };
            if ((int)action < 0) return Reply(false, "COMMAND_NOT_IN_ALLOWLIST");
        }
        catch (JsonException) { return Reply(false, "INVALID_JSON"); }

        lock (_seen)
        {
            if (_seen.Contains(id)) return Reply(false, "REPLAYED_REQUEST");
            if (_seen.Count >= MaxRequests) return Reply(false, "REPLAY_CACHE_FULL");
            // Reserve first to prevent parallel replay, including if dispatch fails.
            _seen.Add(id);
        }
        return dispatch(action) ? Reply(true, "LAB_SERVICE_CHANGED")
                                : Reply(false, "LAB_SERVICE_UNAVAILABLE");
    }

    private static NamedPipeServerStream CreatePipe(string pipeName, bool sameUserTest)
    {
        if (sameUserTest)
        {
            return new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        }

        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (WellKnownSidType sid in new[] {
            WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid
        })
        {
            acl.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(sid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 512, 512, acl);
    }

    internal async Task ServeAsync(string pipeName, bool sameUserTest,
        Func<LabControlAction, bool> dispatcher, CancellationToken token,
        int maxConnections = int.MaxValue)
    {
        for (int n = 0; n < maxConnections && !token.IsCancellationRequested; n++)
        {
            using var pipe = CreatePipe(pipeName, sameUserTest);
            await pipe.WaitForConnectionAsync(token);
            try
            {
                var bytes = new byte[513];
                int count = 0;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(TimeSpan.FromSeconds(4));
                while (count <= 512)
                {
                    int read = await pipe.ReadAsync(bytes.AsMemory(count, 1), timeout.Token);
                    if (read == 0) break;
                    if (bytes[count++] == 10) break;
                }
                string? request = count is > 0 and <= 513 && bytes[count - 1] == 10
                    ? Utf8.GetString(bytes, 0, count - 1).TrimEnd('\r') : null;

                bool osAdmin = false;
                pipe.RunAsClient(() => {
                    using var id = WindowsIdentity.GetCurrent();
                    osAdmin = id.IsSystem || (id.IsAuthenticated &&
                        new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator));
                });
                if (sameUserTest)
                {
                    // Pure CI protocol test permits only this OS-authenticated
                    // same user; it injects fake dispatch and never runs SCM.
                    osAdmin = WindowsIdentity.GetCurrent().IsAuthenticated;
                }
                string result = Process(request, osAdmin,
                    sameUserTest || IsDisposableCiLab(), dispatcher);
                using var writer = new StreamWriter(pipe, Utf8, 512, true) {
                    AutoFlush = true
                };
                await writer.WriteLineAsync(result);
            }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                // Invalid/truncated clients cannot crash the manager service.
            }
        }
    }
}
