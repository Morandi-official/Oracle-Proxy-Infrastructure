using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// Only fixed public, unauthenticated endpoints; never access Gmail messages.
// DNS names are sent to the *existing* loopback SOCKS5 listener. TLS uses the
// normal OS certificate trust check; never install/ignore certificates.
// No browser / system proxy / Oracle / DNS / route / WFP changes.
internal static class GoogleHttpsStageDiagnostic
{
    private static readonly (string Host, string Path, string Label)[] Targets = {
        ("www.google.com", "/generate_204", "Google 204"),
        ("accounts.google.com", "/", "Google 登录"),
        ("mail.google.com", "/mail/", "Gmail 入口")
    };

    internal sealed record Result(bool Complete, string Summary);
    private sealed record Sample(string Label, string Outcome,
        long SocksMs, long TlsMs, long HttpMs);

    internal static async Task<Result> DiagnoseAsync(CancellationToken cancellationToken)
    {
        var results = new List<Sample>();
        foreach (var (host, path, label) in Targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await ProbeAsync(host, path, label, 10880,
                cancellationToken));
        }

        var sb = new StringBuilder();
        sb.AppendLine("R59：Google HTTPS 分阶段诊断（经 SOCKS5，未登录）");
        foreach (Sample r in results)
        {
            sb.Append(r.Label).Append("：").Append(r.Outcome);
            sb.Append("；SOCKS ").Append(r.SocksMs).Append("ms");
            if (r.TlsMs >= 0) sb.Append("，TLS ").Append(r.TlsMs).Append("ms");
            if (r.HttpMs >= 0) sb.Append("，HTTP ").Append(r.HttpMs).Append("ms");
            sb.AppendLine();
        }
        sb.AppendLine("只测试各网址首个 HTTPS 响应，不跟随重定向，不读取邮箱内容。");
        sb.Append("TCP CONNECT 成功不等于 Gmail 页面加载成功；");
        sb.Append("即使本次全部成功，也不能证明 Edge 稳定性或 VPN 防泄漏。");
        return new(true, sb.ToString());
    }

    private static async Task<Sample> ProbeAsync(string host, string path,
        string label, int port, CancellationToken cancellationToken)
    {
        long socksMs = -1, tlsMs = -1, httpMs = -1;
        var watch = Stopwatch.StartNew();
        try
        {
            using var socket = new TcpClient(AddressFamily.InterNetwork);
            using (var step = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken))
            {
                step.CancelAfter(TimeSpan.FromSeconds(7));
                await socket.ConnectAsync(IPAddress.Loopback, port, step.Token);
                var stream = socket.GetStream();
                await stream.WriteAsync(new byte[] { 5, 1, 0 }, step.Token);
                var greeting = new byte[2];
                await stream.ReadExactlyAsync(greeting, step.Token);
                if (greeting[0] != 5 || greeting[1] != 0)
                    return new(label, "SOCKS5 握手拒绝", watch.ElapsedMilliseconds,
                        -1, -1);

                byte[] name = Encoding.ASCII.GetBytes(host);
                byte[] connect = new byte[] { 5, 1, 0, 3, (byte)name.Length }
                    .Concat(name).Concat(new byte[] { 1, 187 }).ToArray();
                await stream.WriteAsync(connect, step.Token);
                var reply = new byte[4];
                await stream.ReadExactlyAsync(reply, step.Token);
                if (reply[0] != 5 || reply[2] != 0)
                    return new(label, "SOCKS5 响应非法", watch.ElapsedMilliseconds,
                        -1, -1);
                if (reply[1] != 0)
                    return new(label, "SOCKS5 CONNECT 被拒，代码 " +
                        reply[1], watch.ElapsedMilliseconds, -1, -1);
                int addressLength;
                if (reply[3] == 1) addressLength = 4;
                else if (reply[3] == 4) addressLength = 16;
                else if (reply[3] == 3)
                {
                    var length = new byte[1];
                    await stream.ReadExactlyAsync(length, step.Token);
                    addressLength = length[0];
                }
                else
                    return new(label, "SOCKS5 地址类型非法",
                        watch.ElapsedMilliseconds, -1, -1);
                var tail = new byte[addressLength + 2];
                await stream.ReadExactlyAsync(tail, step.Token);
                socksMs = watch.ElapsedMilliseconds;
            }

            using var tls = new SslStream(socket.GetStream(), leaveInnerStreamOpen: false);
            // Stage 2: certificate authentication with normal strict
            // platform validation; no RemoteCertificateValidationCallback.
            using (var step = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken))
            {
                step.CancelAfter(TimeSpan.FromSeconds(8));
                var options = new SslClientAuthenticationOptions {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.None
                };
                await tls.AuthenticateAsClientAsync(options, step.Token);
                tlsMs = watch.ElapsedMilliseconds - socksMs;
            }

            // Stage 3: read HTTP status only. Do not follow authentication
            // redirects, send cookies, or record any response headers/body.
            using (var step = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken))
            {
                step.CancelAfter(TimeSpan.FromSeconds(8));
                byte[] request = Encoding.ASCII.GetBytes(
                    "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "User-Agent: OracleProxy-R59-Connectivity-Test\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n");
                await tls.WriteAsync(request, step.Token);
                var firstLine = new List<byte>(160);
                var single = new byte[1];
                while (firstLine.Count < 160)
                {
                    int read = await tls.ReadAsync(single, step.Token);
                    if (read != 1)
                        return new(label, "TLS 成功，但未收到 HTTP 状态行",
                            socksMs, tlsMs, watch.ElapsedMilliseconds - socksMs - tlsMs);
                    if (single[0] == '\n') break;
                    firstLine.Add(single[0]);
                }
                httpMs = watch.ElapsedMilliseconds - socksMs - tlsMs;
                string responseLine = Encoding.ASCII.GetString(
                    firstLine.ToArray()).Trim();
                if (!responseLine.StartsWith("HTTP/1.", StringComparison.Ordinal))
                    return new(label, "TLS 成功，但 HTTP 状态行异常",
                        socksMs, tlsMs, httpMs);
                string[] parts = responseLine.Split(' ', 3,
                    StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || !int.TryParse(parts[1], out int status) ||
                    status < 100 || status > 599)
                    return new(label, "TLS 成功，但 HTTP 状态码异常",
                        socksMs, tlsMs, httpMs);
                return new(label, "TLS 验证通过、HTTP " + status,
                    socksMs, tlsMs, httpMs);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            string stage = socksMs < 0 ? "SOCKS CONNECT" :
                tlsMs < 0 ? "TLS 握手" : "HTTP 首响应";
            return new(label, stage + " 超时", socksMs < 0 ?
                watch.ElapsedMilliseconds : socksMs, tlsMs, httpMs);
        }
        catch (AuthenticationException)
        {
            return new(label, "TLS 证书验证或握手失败", socksMs, tlsMs, httpMs);
        }
        catch (IOException)
        {
            return new(label, socksMs < 0 ? "SOCKS 连接中断" :
                tlsMs < 0 ? "TLS 握手连接中断" : "HTTP 响应中断",
                socksMs, tlsMs, httpMs);
        }
        catch (SocketException)
        {
            return new(label, "本地 SOCKS5 不可达", socksMs, tlsMs, httpMs);
        }
    }

    // CI-only mock local SOCKS5 -> self-signed TLS endpoint.
    // A strict TLS client MUST reject this test certificate.
    // No external network, no mock Gmail response, no trust bypass.
    internal static async Task<bool> SelfTestAsync()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=accounts.google.com", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(10));
        var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            int port = ((IPEndPoint)server.LocalEndpoint).Port;
            Task<bool> mock = Task.Run(async () =>
            {
                using var conn = await server.AcceptTcpClientAsync(cancel.Token);
                var stream = conn.GetStream();
                var greeting = new byte[3];
                await stream.ReadExactlyAsync(greeting, cancel.Token);
                if (!greeting.AsSpan().SequenceEqual(new byte[] { 5, 1, 0 }))
                    return false;
                await stream.WriteAsync(new byte[] { 5, 0 }, cancel.Token);
                byte[] header = new byte[5];
                await stream.ReadExactlyAsync(header, cancel.Token);
                if (header[0] != 5 || header[1] != 1 || header[3] != 3)
                    return false;
                byte[] hostname = new byte[header[4]];
                await stream.ReadExactlyAsync(hostname, cancel.Token);
                byte[] tcpPort = new byte[2];
                await stream.ReadExactlyAsync(tcpPort, cancel.Token);
                if (Encoding.ASCII.GetString(hostname) != "accounts.google.com" ||
                    tcpPort[0] != 1 || tcpPort[1] != 187)
                    return false;
                await stream.WriteAsync(new byte[] {
                    5, 0, 0, 1, 127, 0, 0, 1, 0, 0
                }, cancel.Token);
                using var ssl = new SslStream(stream, false);
                try { await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions {
                        ServerCertificate = cert,
                        EnabledSslProtocols = SslProtocols.None,
                        ClientCertificateRequired = false,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    }, cancel.Token); }
                catch (AuthenticationException) { }
                catch (IOException) { }
                return true;
            }, cancel.Token);
            Sample result = await ProbeAsync("accounts.google.com", "/", "mock",
                port, cancel.Token);
            bool protocolSeen = await mock.WaitAsync(cancel.Token);
            bool pass = protocolSeen && result.Outcome ==
                "TLS 证书验证或握手失败" && result.SocksMs >= 0;
            if (pass)
                Console.WriteLine(
                    "R59_TLS_CERTIFICATE_VALIDATION_AND_SOCKS_DOMAIN_NO_DIRECT_PASS");
            return pass;
        }
        finally { server.Stop(); }
    }
}
