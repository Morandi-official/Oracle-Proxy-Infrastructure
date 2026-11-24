using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace OracleProxy.Tailscale;

internal static class ExitCheck
{
    private static readonly Uri V4 = new("https://1.1.1.1/cdn-cgi/trace");
    private static readonly Uri V6 = new("https://[2606:4700:4700::1111]/cdn-cgi/trace");

    internal static async Task Verify(DaemonProcess daemon, ExitProfile profile, CancellationToken cancel)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            while (true)
            {
                var status = await daemon.Control.ReadState(limit.Token);
                var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(
                    value => value.Name == daemon.AdapterName && value.OperationalStatus == OperationalStatus.Up);
                if (status.State == "Running" && status.ExitId == profile.NodeId.ToString(CultureInfo.InvariantCulture)
                    && adapter is not null)
                {
                    var v4 = Matches(adapter, V4, profile.IPv4, AddressFamily.InterNetwork, limit.Token);
                    var v6 = Matches(adapter, V6, profile.IPv6, AddressFamily.InterNetworkV6, limit.Token);
                    if ((await Task.WhenAll(v4, v6)).All(value => value)) return;
                }
                await Task.Delay(125, limit.Token);
            }
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            throw new IOException("EXIT_NOT_VERIFIED");
        }
    }

    private static async Task<bool> Matches(NetworkInterface adapter, Uri address, string expected,
        AddressFamily family, CancellationToken cancel)
    {
        var source = adapter.GetIPProperties().UnicastAddresses.Select(value => value.Address)
            .FirstOrDefault(value => value.AddressFamily == family && !value.IsIPv6LinkLocal);
        if (source is null) return false;
        using var http = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromMilliseconds(1500),
            ConnectCallback = async (_, cancellation) =>
            {
                var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(source, 0));
                    await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(address.Host.Trim('[', ']')), 443), cancellation);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            },
        }) { Timeout = TimeSpan.FromSeconds(3), MaxResponseContentBufferSize = 8192 };
        try
        {
            var result = await http.GetStringAsync(address, cancel);
            var ip = result.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
            return ip is not null && IPAddress.TryParse(ip[3..].Trim(), out var observed)
                && observed.Equals(IPAddress.Parse(expected));
        }
        catch (HttpRequestException) { return false; }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested) { return false; }
    }
}
