using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// R57: actively checks ONLY the app-local SOCKS5 proxy with two HTTPS IP
// echo services. An ordinary browser tab DOES NOT inherit this proxy.
// No system proxy, DNS, WFP, route, registry, key or SSH state is changed.
internal static class ExitIpProbe
{
    private static readonly Uri[] Endpoints = {
        new("https://api.ipify.org/"),
        new("https://checkip.amazonaws.com/")
    };
    private sealed record SingleResult(string Provider, bool Success,
        IPAddress? ExitIp, string Reason);

    internal sealed record Report(bool Verified, string Summary);

    private static HttpClient CreateClient(int proxyPort)
    {
        // Explicit per-request proxy, never HttpClient.DefaultProxy nor
        // Windows system proxy. .NET 8's "socks5" passes the target
        // hostname to the SOCKS5 server for remote resolution.
        var handler = new SocketsHttpHandler
        {
            UseProxy = true,
            Proxy = new WebProxy(new Uri(
                "socks5://127.0.0.1:" + proxyPort.ToString(
                    System.Globalization.CultureInfo.InvariantCulture)))
            {
                BypassProxyOnLocal = false
            },
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.Zero
        };
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    private static async Task<SingleResult> CheckAsync(Uri endpoint, int port,
        CancellationToken cancellationToken)
    {
        using var client = CreateClient(port);
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
            using var response = await client.SendAsync(req,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK)
                return new(endpoint.Host, false, null, "非 HTTP 200");
            await using var stream = await response.Content.ReadAsStreamAsync(
                cancellationToken);
            byte[] buffer = new byte[80];
            int total = 0;
            while (total < buffer.Length)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(total),
                    cancellationToken);
                if (n == 0) break;
                total += n;
            }
            if (total is <= 0 or >= 80)
                return new(endpoint.Host, false, null, "IP 响应长度异常");
            string body = Encoding.ASCII.GetString(buffer, 0, total).Trim();
            if (!IPAddress.TryParse(body, out IPAddress? parsed) ||
                parsed.AddressFamily != AddressFamily.InterNetwork)
                return new(endpoint.Host, false, null, "未返回有效 IPv4");
            return new(endpoint.Host, true, parsed, "HTTP 200");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new(endpoint.Host, false, null, "超时");
        }
        catch (HttpRequestException)
        {
            return new(endpoint.Host, false, null, "SOCKS5/HTTPS 连接失败");
        }
        catch (IOException)
        {
            return new(endpoint.Host, false, null, "HTTP 读取失败");
        }
    }

    internal static async Task<Report> VerifyAsync(string expectedSshHost,
        CancellationToken cancellationToken)
    {
        // Run sequentially to avoid mistaken "success" after an incomplete
        // previous request; both independent providers must return matching IP.
        SingleResult a = await CheckAsync(Endpoints[0], 10880, cancellationToken);
        SingleResult b = await CheckAsync(Endpoints[1], 10880, cancellationToken);
        if (!a.Success || !b.Success)
            return new(false,
                "代理出口未完整验证：" +
                a.Provider + " " + a.Reason + "；" +
                b.Provider + " " + b.Reason + "。普通 Edge 不会自动使用代理。");
        if (!a.ExitIp!.Equals(b.ExitIp))
            return new(false, "代理出口不一致，拒绝确认 Oracle 身份。");
        if (IPAddress.TryParse(expectedSshHost, out IPAddress? sshIp) &&
            !sshIp.Equals(a.ExitIp))
            return new(false, "两站 HTTP 200 但出口 " + a.ExitIp +
                " 与输入的 Oracle SSH 地址不同，请核实是否为出站 NAT。");

        if (!IPAddress.TryParse(expectedSshHost, out _))
            return new(true, "两站 HTTP 200，SOCKS5 出口 " + a.ExitIp +
                " 一致；SSH 主机使用域名，仍需独立核对 Oracle 公网 IP。");

        return new(true, "SOCKS5 验证成功：两站 HTTP 200，出口 " +
            a.ExitIp + " 与 Oracle SSH 公网 IP 一致。");
    }

    // Disposable CI only: a fake local SOCKS5 peer rejects CONNECT and
    // records the target hostname. It must NOT initiate a public request.
    // This proves explicit loopback routing and remote SOCKS DNS behavior,
    // and verifies failed SOCKS5 cannot silently fall back to direct.
    internal static async Task<bool> SelfTestAsync()
    {
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        int port = ((IPEndPoint)server.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(9));
        var accepted = Task.Run(async () =>
        {
            using var socket = await server.AcceptTcpClientAsync(timeout.Token);
            using var stream = socket.GetStream();
            byte[] greeting = new byte[3];
            await stream.ReadExactlyAsync(greeting, timeout.Token);
            if (!greeting.AsSpan().SequenceEqual(new byte[] { 5, 1, 0 }))
                return false;
            await stream.WriteAsync(new byte[] { 5, 0 }, timeout.Token);
            byte[] connect = new byte[4];
            await stream.ReadExactlyAsync(connect, timeout.Token);
            if (connect[0] != 5 || connect[1] != 1 ||
                connect[2] != 0 || connect[3] != 3)
                return false;
            byte[] size = new byte[1];
            await stream.ReadExactlyAsync(size, timeout.Token);
            if (size[0] is 0 or > 128) return false;
            byte[] hostname = new byte[size[0]];
            await stream.ReadExactlyAsync(hostname, timeout.Token);
            byte[] destinationPort = new byte[2];
            await stream.ReadExactlyAsync(destinationPort, timeout.Token);
            // Decline before any outbound DNS lookup or public packets.
            await stream.WriteAsync(new byte[] {
                5, 5, 0, 1, 127, 0, 0, 1, 0, 0
            }, timeout.Token);
            return Encoding.ASCII.GetString(hostname) == "example.invalid" &&
                   destinationPort[0] == 1 && destinationPort[1] == 187;
        }, timeout.Token);
        var result = await CheckAsync(new Uri("https://example.invalid/"),
            port, timeout.Token);
        bool observed = await accepted.WaitAsync(timeout.Token);
        if (!result.Success && observed)
            Console.WriteLine("R57_SOCKS5_EXPLICIT_PROXY_REMOTE_DNS_NO_FALLBACK_PASS");
        return !result.Success && observed;
    }
}
