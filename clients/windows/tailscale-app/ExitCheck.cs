using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace OracleProxy.Tailscale;

internal static class ExitCheck
{
    private static readonly Uri V4 = new("https://1.1.1.1/cdn-cgi/trace");
    private static readonly Uri V6 = new("https://[2606:4700:4700::1111]/cdn-cgi/trace");

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

            // Start fresh sockets once the selected exit is present. An earlier
            // attempt can retain a pending connect across the route change.
            await Task.WhenAll(
                VerifyFamily(daemon.AdapterName, V4, profile.IPv4, AddressFamily.InterNetwork,
                    timing is null ? null : () => timing("ipv4_verified"), limit.Token),
                VerifyFamily(daemon.AdapterName, V6, profile.IPv6, AddressFamily.InterNetworkV6,
                    timing is null ? null : () => timing("ipv6_verified"), limit.Token));
            var verified = await daemon.Control.ReadState(limit.Token);
            if (verified.State != "Running" || verified.ExitId != exit)
                throw new IOException("EXIT_NOT_VERIFIED");
        }
        catch (OperationCanceledException error) when (!cancel.IsCancellationRequested)
        {
            throw new IOException(mapReady ? "EXIT_NOT_VERIFIED" : "TAILSCALE_COORDINATOR_TIMEOUT", error);
        }
    }

    private static NetworkInterface? Adapter(string name) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(
            value => value.Name == name && value.OperationalStatus == OperationalStatus.Up);

    private static async Task VerifyFamily(string adapter, Uri target, string expected, AddressFamily family,
        Action? verified, CancellationToken cancel)
    {
        int probes = 0;
        while (true)
        {
            cancel.ThrowIfCancellationRequested();
            var source = Adapter(adapter)?.GetIPProperties().UnicastAddresses
                .Select(value => value.Address)
                .FirstOrDefault(value => value.AddressFamily == family && !value.IsIPv6LinkLocal);
            if (source is not null)
            {
                // Abort the first stalled socket promptly while interfaces settle.
                // Later attempts retain the former budgets for slower networks.
                bool first = probes++ == 0;
                if (await Matches(source, target, IPAddress.Parse(expected), family, first, cancel))
                {
                    verified?.Invoke();
                    return;
                }
            }
            await Task.Delay(probes < 2 ? 25 : 125, cancel);
        }
    }

    private static async Task<bool> Matches(IPAddress source, Uri target, IPAddress expected, AddressFamily family,
        bool first, CancellationToken cancel)
    {
        using var http = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromMilliseconds(first ? 600 : 1500),
            ConnectCallback = async (_, cancellation) =>
            {
                var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(source, 0));
                    await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(target.Host.Trim('[', ']')), 443), cancellation);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            },
        }) { Timeout = TimeSpan.FromMilliseconds(first ? 1200 : 3000), MaxResponseContentBufferSize = 8192 };
        try
        {
            var result = await http.GetStringAsync(target, cancel);
            var ip = result.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
            return ip is not null && IPAddress.TryParse(ip[3..].Trim(), out var observed)
                && observed.Equals(expected);
        }
        catch (HttpRequestException) { return false; }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested) { return false; }
    }
}
