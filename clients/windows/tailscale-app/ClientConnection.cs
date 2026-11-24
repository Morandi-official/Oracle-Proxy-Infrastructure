using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace OracleProxy.Tailscale;

internal static class ClientConnection
{
    internal static string StateFor(string root, string username) =>
        Path.Combine(root, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(username))));

    internal static string Device(string state)
    {
        Directory.CreateDirectory(state);
        string file = Path.Combine(state, "device");
        if (!File.Exists(file))
            File.WriteAllText(file, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        string identity = File.ReadAllText(file);
        if (identity.Length != 64 || !identity.All(char.IsAsciiHexDigitLower))
            throw new IOException("INVALID_PROXY_DEVICE_ID");
        return identity;
    }

    internal static async Task<(DaemonProcess Daemon, ExitProfile Profile)> Open(AccountClient account, string session, string state,
        CancellationToken cancel, Action<string>? progress = null, Action<string, long>? timing = null)
    {
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        var startedAt = Stopwatch.GetTimestamp();
        void Mark(string stage) => timing?.Invoke(stage, (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);

        async Task<T> Record<T>(Task<T> task, string stage)
        {
            T result = await task.ConfigureAwait(false);
            Mark(stage);
            return result;
        }

        // Let the account TLS request run while Windows starts the native engine.
        progress?.Invoke("ACCOUNT_PROFILE");
        var profileTask = Record(account.Profile(session, false, attempt.Token), "account_ready");
        var daemonTask = Record(DaemonProcess.Start(Path.Combine(AppContext.BaseDirectory, "engine", "tailscaled.exe"),
            state, attempt.Token, timing is null ? null : Mark), "daemon_ready");
        try
        {
            var profile = await profileTask;
            progress?.Invoke("DAEMON_PROFILE");
            var daemon = await daemonTask;
            if (profile.Key is not null)
            {
                progress?.Invoke("ENROLLMENT_START");
                await daemon.Control.Enroll(profile.Coordinator, profile.Key, attempt.Token);
                Mark("enrollment_started");
                using var registration = CancellationTokenSource.CreateLinkedTokenSource(attempt.Token);
                registration.CancelAfter(TimeSpan.FromSeconds(10));
                progress?.Invoke("COORDINATOR_NODE_KEY");
                while (!(await daemon.Control.ReadState(registration.Token)).HasNodeKey)
                    await Task.Delay(125, registration.Token);
                Mark("node_key_ready");
                progress?.Invoke("ACCOUNT_CONFIRM");
                while (true)
                {
                    try
                    {
                        await account.Profile(session, true, registration.Token);
                        break;
                    }
                    catch (IOException error) when (error.Message == "TAILSCALE_ENROLLMENT_PENDING")
                    {
                        await Task.Delay(125, registration.Token);
                    }
                }
                Mark("account_confirmed");
            }
            progress?.Invoke("SELECT_EXIT");
            await daemon.Control.SelectExitNode(profile.NodeId, attempt.Token);
            Mark("exit_selected");
            progress?.Invoke("VERIFY_EXIT");
            await ExitCheck.Verify(daemon, profile, attempt.Token, timing is null ? null : Mark);
            attempt.Token.ThrowIfCancellationRequested();
            return (daemon, profile);
        }
        catch
        {
            await attempt.CancelAsync();
            DaemonProcess? started = null;
            try { started = await daemonTask; }
            catch { } // The original startup or account failure is preserved.
            if (started is not null)
            {
                try { await started.DisposeAsync(); }
                catch (Exception cleanup) { throw new IOException("TAILSCALE_DAEMON_CLEANUP_FAILED", cleanup); }
            }
            throw;
        }
    }
}
