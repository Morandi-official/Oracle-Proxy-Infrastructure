using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace OracleProxy.Tailscale;

internal static class ClientConnection
{
    private static readonly IPAddress PublicV4 = IPAddress.Parse("1.1.1.1");
    private static readonly IPAddress PublicV6 = IPAddress.Parse("2606:4700:4700::1111");

    private static bool UsesOrdinaryRoute(IPAddress destination, IPInterfaceProperties owned)
    {
        using var socket = new Socket(destination.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            // Connecting a datagram socket selects a source address without sending a packet.
            socket.Connect(new IPEndPoint(destination, 443));
            return socket.LocalEndPoint is IPEndPoint source &&
                !owned.UnicastAddresses.Any(value => value.Address.Equals(source.Address));
        }
        catch (SocketException error) when (destination.AddressFamily == AddressFamily.InterNetworkV6 &&
            error.SocketErrorCode is SocketError.NetworkUnreachable or SocketError.HostUnreachable or
                SocketError.AddressNotAvailable)
        {
            return true;
        }
    }

    private static bool HasConfiguredDns(IPInterfaceProperties owned) =>
        owned.DnsAddresses.Any(value => value.ToString().Split('%', 2)[0] is not
            ("fec0:0:0:ffff::1" or "fec0:0:0:ffff::2" or "fec0:0:0:ffff::3"));

    internal static async Task<bool> TryRestoreDirect(DaemonProcess daemon, CancellationToken cancel, Action<string>? fallback = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        string waitingFor = "clear_exit";
        try
        {
            await daemon.Control.ClearExit(deadline.Token);
            while (true)
            {
                var state = await daemon.Control.ReadState(deadline.Token);
                var adapter = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(value => value.Name == daemon.AdapterName)?.GetIPProperties();
                if (state is not { State: "Running", HasNodeKey: true, ExitId: "" })
                    waitingFor = "exit_selection";
                else if (adapter is null)
                    waitingFor = "owned_adapter";
                else if (HasConfiguredDns(adapter))
                    waitingFor = "owned_dns";
                else if (!UsesOrdinaryRoute(PublicV4, adapter))
                    waitingFor = "ipv4_route";
                else if (!UsesOrdinaryRoute(PublicV6, adapter))
                    waitingFor = "ipv6_route";
                else
                    return true;
                await Task.Delay(50, deadline.Token);
            }
        }
        catch (Exception error) when (IsRecoverable(error, cancel) || error is NetworkInformationException or SocketException)
        {
            fallback?.Invoke(waitingFor);
            return false;
        }
    }

    private static bool IsRecoverable(Exception error, CancellationToken cancel) =>
        !cancel.IsCancellationRequested && error is IOException or HttpRequestException or OperationCanceledException;

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
        CancellationToken cancel, Action<string>? progress = null, Action<string, long>? timing = null,
        DaemonProcess? retained = null, ExitProfile? previous = null)
    {
        if (retained is not null)
        {
            bool reused = false;
            try
            {
                progress?.Invoke("RETAINED_ACCOUNT_PROFILE");
                var profile = await account.Profile(session, false, cancel);
                if (profile.Key is null && previous?.Coordinator == profile.Coordinator)
                {
                    try
                    {
                        var stateBefore = await retained.Control.ReadState(cancel);
                        if (stateBefore is { State: "Running", HasNodeKey: true, ExitId: "" })
                        {
                            progress?.Invoke("RETAINED_SELECT_EXIT");
                            await retained.Control.SelectExitNode(profile.NodeId, cancel);
                            await ExitCheck.Verify(retained, profile, cancel);
                            cancel.ThrowIfCancellationRequested();
                            reused = true;
                            return (retained, profile);
                        }
                    }
                    catch (Exception error) when (IsRecoverable(error, cancel)) { }
                }
            }
            finally
            {
                if (!reused) await retained.DisposeAsync();
            }
        }
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
            state, attempt.Token, timing is null ? null : Mark, authorization: profileTask), "daemon_ready");
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
