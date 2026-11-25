using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OracleProxy.Tailscale;

internal static class ExitCheck
{
    private static readonly Uri V4 = new("https://1.1.1.1/cdn-cgi/trace");
    private static readonly Uri V6 = new("https://[2606:4700:4700::1111]/cdn-cgi/trace");
    private static readonly Uri Backup = new("https://checkip.global.api.aws/");
    private static readonly ConditionalWeakTable<DaemonProcess, ProofPreference> LastProof = new();

    private sealed record ProofPreference(long NodeId, string IPv4, string IPv6, bool IPv4Backup, bool IPv6Backup);

    internal static async Task Verify(DaemonProcess daemon, ExitProfile profile, CancellationToken cancel,
        Action<string>? timing = null, bool slowCoordinator = false)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(slowCoordinator ? 35 : 10));
        bool mapReady = false;

        try
        {
            string exit = profile.NodeId.ToString(CultureInfo.InvariantCulture);
            var waiting = Stopwatch.StartNew();
            while (true)
            {
                var status = await daemon.Control.ReadState(limit.Token);
                if (status.State == "Running" && status.ExitId == exit && Adapter(daemon.AdapterName) is not null)
                    break;
                await Task.Delay(waiting.ElapsedMilliseconds < 1000 ? 25 : 125, limit.Token);
            }
            timing?.Invoke("exit_map_ready");
            mapReady = true;
            limit.CancelAfter(TimeSpan.FromSeconds(10));

            LastProof.TryGetValue(daemon, out var previous);
            if (previous?.NodeId != profile.NodeId || previous.IPv4 != profile.IPv4 || previous.IPv6 != profile.IPv6)
                previous = null;
            int alternateDelay = previous is null ? 250 : 100;
            // Start fresh sockets once the selected exit is present. An earlier
            // attempt can retain a pending connect across the route change.
            var backupWinners = await Task.WhenAll(
                VerifyFamily(daemon.AdapterName, V4, profile.IPv4, AddressFamily.InterNetwork,
                    previous?.IPv4Backup == true, alternateDelay, "ipv4", timing, limit.Token),
                VerifyFamily(daemon.AdapterName, V6, profile.IPv6, AddressFamily.InterNetworkV6,
                    previous?.IPv6Backup == true, alternateDelay, "ipv6", timing, limit.Token));
            var verified = await daemon.Control.ReadState(limit.Token);
            if (verified.State != "Running" || verified.ExitId != exit)
                throw new IOException("EXIT_NOT_VERIFIED");
            LastProof.AddOrUpdate(daemon, new ProofPreference(profile.NodeId, profile.IPv4, profile.IPv6,
                backupWinners[0], backupWinners[1]));
        }
        catch (OperationCanceledException error) when (!cancel.IsCancellationRequested)
        {
            throw new IOException(mapReady ? "EXIT_NOT_VERIFIED" : "TAILSCALE_COORDINATOR_TIMEOUT", error);
        }
    }

    private static NetworkInterface? Adapter(string name) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(
            value => value.Name == name && value.OperationalStatus == OperationalStatus.Up);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestInterfaceEx([In] byte[] destination, out uint interfaceIndex);

    private static bool UsesAdapterRoute(IPInterfaceProperties adapter, byte[] destination, AddressFamily family)
    {
        int index = family == AddressFamily.InterNetwork ? adapter.GetIPv4Properties().Index :
            adapter.GetIPv6Properties().Index;
        return GetBestInterfaceEx(destination, out uint selectedIndex) == 0 && selectedIndex == index;
    }

    private static async Task<bool> VerifyFamily(string adapter, Uri target, string expected, AddressFamily family,
        bool backupFirst, int alternateDelay, string milestone, Action<string>? timing, CancellationToken cancel)
    {
        var endpoint = new IPEndPoint(IPAddress.Parse(target.Host.Trim('[', ']')), target.Port);
        byte[] destination = endpoint.Serialize().Buffer.ToArray();
        var expectedAddress = IPAddress.Parse(expected);
        var settling = Stopwatch.StartNew();
        int probes = 0;
        while (true)
        {
            cancel.ThrowIfCancellationRequested();
            var network = Adapter(adapter)?.GetIPProperties();
            var source = network?.UnicastAddresses
                .Select(value => value.Address)
                .FirstOrDefault(value => value.AddressFamily == family && !value.IsIPv6LinkLocal);
            bool routeReady = source is not null && probes == 0 && UsesAdapterRoute(network!, destination, family);
            // Wait briefly for the OS to select the tunnel route. A bound HTTPS proof is
            // still decisive if interface enumeration does not reflect the transition.
            if (source is not null && (routeReady || probes > 0 || settling.ElapsedMilliseconds >= 250))
            {
                // Abort the first stalled socket promptly while interfaces settle.
                // Later attempts retain the former budgets for slower networks.
                bool first = probes++ == 0;
                if (routeReady)
                    timing?.Invoke($"{milestone}_route_ready");
                if (first && backupFirst)
                    timing?.Invoke($"{milestone}_backup_first");
                var result = await Probe(source, expectedAddress, family, first,
                    backupFirst ? Backup : target, backupFirst ? target : Backup, alternateDelay,
                    milestone, timing, cancel);
                cancel.ThrowIfCancellationRequested();
                if (result is not null)
                {
                    timing?.Invoke($"{milestone}_verified");
                    if (result == Backup)
                        timing?.Invoke($"{milestone}_backup_verified");
                    return result == Backup;
                }
            }
            await Task.Delay(probes < 2 ? 25 : 125, cancel);
        }
    }

    private static async Task<Uri?> Probe(IPAddress source, IPAddress expected, AddressFamily family, bool first,
        Uri preferredTarget, Uri alternateTarget, int alternateDelay, string milestone, Action<string>? timing,
        CancellationToken cancel)
    {
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        try
        {
            var preferred = VerifyTarget(source, preferredTarget, expected, family, first, milestone, timing, attempt.Token);
            if (await Task.WhenAny(preferred, Task.Delay(alternateDelay, attempt.Token)) == preferred &&
                await preferred is { } verified)
                return verified;

            cancel.ThrowIfCancellationRequested();
            var alternate = VerifyTarget(source, alternateTarget, expected, family, first, milestone, timing, attempt.Token);
            var winner = await Task.WhenAny(preferred, alternate);
            return await winner ?? await (winner == preferred ? alternate : preferred);
        }
        finally
        {
            attempt.Cancel();
        }
    }

    private static async Task<Uri?> VerifyTarget(IPAddress source, Uri target, IPAddress expected, AddressFamily family,
        bool first, string milestone, Action<string>? timing, CancellationToken cancel)
    {
        string? phase = first && timing is not null ? $"{milestone}_{(target == Backup ? "backup" : "primary")}_first" : null;
        void Mark(string step)
        {
            if (phase is not null) timing?.Invoke($"{phase}_{step}");
        }

        var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromMilliseconds(first ? 600 : 1500),
            ConnectCallback = async (context, cancellation) =>
            {
                var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.NoDelay = true;
                    socket.Bind(new IPEndPoint(source, 0));
                    var endpoint = context.DnsEndPoint;
                    if (IPAddress.TryParse(endpoint.Host.Trim('[', ']'), out var literal))
                    {
                        await socket.ConnectAsync(new IPEndPoint(literal, endpoint.Port), cancellation);
                    }
                    else
                    {
                        var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, family, cancellation);
                        if (addresses.Length == 0)
                            throw new SocketException((int)SocketError.HostNotFound);
                        Mark("dns_ready");
                        await socket.ConnectAsync(addresses, endpoint.Port, cancellation);
                    }
                    Mark("tcp_connected");
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            },
        };
        if (phase is not null)
        {
            // Report when the authenticated transport becomes available to HTTP.
            handler.PlaintextStreamFilter = (context, _) =>
            {
                Mark("tls_ready");
                return ValueTask.FromResult(context.PlaintextStream);
            };
        }
        using var http = new HttpClient(handler)
            { Timeout = TimeSpan.FromMilliseconds(first ? 1200 : 3000), MaxResponseContentBufferSize = 8192 };
        try
        {
            Mark("started");
            var result = await http.GetStringAsync(target, cancel);
            Mark("response_received");
            var ip = target == Backup ? result.Trim() : result.Split('\n')
                .FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal))?[3..].Trim();
            return IPAddress.TryParse(ip, out var observed) && observed.Equals(expected) ? target : null;
        }
        catch (HttpRequestException) { return null; }
        catch (OperationCanceledException) { return null; }
    }
}
