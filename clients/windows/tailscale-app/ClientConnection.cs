using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace OracleProxy.Tailscale;

internal static class ClientConnection
{
    private static readonly IPAddress PublicV4Lower = IPAddress.Parse("1.1.1.1");
    private static readonly IPAddress PublicV4Upper = IPAddress.Parse("208.67.222.222");
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

    internal static async Task<bool> TryRestoreDirect(DaemonProcess daemon, CancellationToken cancel,
        Action<string>? fallback = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(6));
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
                else if (!UsesOrdinaryRoute(PublicV4Lower, adapter) || !UsesOrdinaryRoute(PublicV4Upper, adapter))
                    waitingFor = "ipv4_route";
                else if (!UsesOrdinaryRoute(PublicV6, adapter))
                    waitingFor = "ipv6_route";
                else if (daemon.HasExited)
                {
                    fallback?.Invoke("daemon_exited");
                    return false;
                }
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
        var startedAt = Stopwatch.GetTimestamp();
        void Mark(string stage) => timing?.Invoke(stage, (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);

        ExitProfile profile;
        bool reused = false;
        try
        {
            progress?.Invoke(retained is null ? "ACCOUNT_PROFILE" : "RETAINED_ACCOUNT_PROFILE");
            profile = await account.AuthorizeConnection(session, cancel);
            Mark(retained is null ? "account_ready" : "retained_account_ready");
            if (retained is not null && profile.Key is null && previous?.Coordinator == profile.Coordinator)
            {
                try
                {
                    var stateBefore = await retained.Control.ReadState(cancel);
                    if (stateBefore is { State: "Running", HasNodeKey: true, ExitId: "" })
                    {
                        progress?.Invoke("RETAINED_SELECT_EXIT");
                        await retained.Control.SelectExitNode(profile.NodeId, cancel);
                        Mark("retained_exit_selected");
                        await ExitCheck.Verify(retained, profile, cancel, timing is null ? null : Mark);
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
            if (retained is not null && !reused) await retained.DisposeAsync();
        }

        var coordinator = account.CoordinatorRoute;
        if (coordinator.Address is not null) Mark("coordinator_dns_hint_ready");
        if (coordinator.Proxy is not null) Mark("coordinator_proxy_hint_ready");
        if (coordinator.FallbackProxy is not null) Mark("coordinator_fallback_proxy_hint_ready");
        progress?.Invoke("DAEMON_PROFILE");
        var daemon = await DaemonProcess.Start(Path.Combine(AppContext.BaseDirectory, "engine", "tailscaled.exe"),
            state, cancel, timing is null ? null : Mark, coordinator: coordinator);
        Mark("daemon_ready");
        try
        {
            if (profile.Key is not null)
            {
                progress?.Invoke("ENROLLMENT_START");
                await daemon.Control.Enroll(profile.Coordinator, profile.Key, cancel);
                Mark("enrollment_started");
                using var registration = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                registration.CancelAfter(TimeSpan.FromSeconds(55));
                bool nodeKeyReady = false;
                try
                {
                    progress?.Invoke("COORDINATOR_NODE_KEY");
                    while (!(await daemon.Control.ReadState(registration.Token)).HasNodeKey)
                        await Task.Delay(125, registration.Token);
                    Mark("node_key_ready");
                    nodeKeyReady = true;
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
                    profile = profile with { Key = null };
                }
                catch (OperationCanceledException error) when (!cancel.IsCancellationRequested)
                {
                    throw new IOException(nodeKeyReady ? "TAILSCALE_ENROLLMENT_TIMEOUT" : "TAILSCALE_COORDINATOR_TIMEOUT", error);
                }
            }
            else
            {
                if (!(await daemon.Control.ReadState(cancel)).HasNodeKey)
                    throw new IOException("TAILSCALE_LOCAL_REGISTRATION_MISSING");
                Mark("persisted_node_key_ready");
            }
            progress?.Invoke("SELECT_EXIT");
            await daemon.Control.SelectExitNode(profile.NodeId, cancel);
            Mark("exit_selected");
            progress?.Invoke("VERIFY_EXIT");
            await ExitCheck.Verify(daemon, profile, cancel, timing is null ? null : Mark, slowCoordinator: true);
            cancel.ThrowIfCancellationRequested();
            return (daemon, profile);
        }
        catch
        {
            try { await daemon.DisposeAsync(); }
            catch (Exception cleanup) { throw new IOException("TAILSCALE_DAEMON_CLEANUP_FAILED", cleanup); }
            throw;
        }
    }
}
