using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// Diagnostics only: no system proxy, DNS, routes, WFP, Windows service,
// firewall or server configuration modification. This is NOT IPv4 pinning
// for real browser traffic. It compares raw TCP SOCKS5 CONNECT replies.
internal static class SocksAddressFamilyDiagnostic
{
    internal sealed record Result(bool DiagnosticCompleted, string Summary);
    private sealed record Probe(bool Succeeded, string Status);

    private const string Destination = "accounts.google.com";
    private const int Port = 443;

    private static ProcessStartInfo GetSshQueryInfo(SshInput.Validated user)
    {
        string ssh = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.Windows), "System32", "OpenSSH", "ssh.exe");
        if (!File.Exists(ssh))
            throw new InvalidOperationException("Windows OpenSSH 客户端不存在。");
        var start = new ProcessStartInfo(ssh)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = false, RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string arg in new[] {
            "-F", "none",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=8",
            "-o", "PermitLocalCommand=no",
            "-o", "ControlMaster=no",
            "-o", "IdentitiesOnly=yes",
            "-i", user.KeyPath,
            "-p", user.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-l", user.User,
            "--", user.Host,
            // Read-only remote resolution using the server's own A records.
            // All remote-command tokens fixed in source, never user supplied.
            "getent", "ahostsv4", Destination
        })
            start.ArgumentList.Add(arg);
        return start;
    }

    internal static async Task<IPAddress?> GetOracleARecordAsync(
        SshInput.Validated user, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        using var child = ChildProcessLease.Start(GetSshQueryInfo(user));
        Task drain = child.Process.StandardError.BaseStream.CopyToAsync(
            Stream.Null, timeout.Token);
        try
        {
            string output = await child.Process.StandardOutput.ReadToEndAsync(
                timeout.Token);
            await child.Process.WaitForExitAsync(timeout.Token);
            if (child.Process.ExitCode != 0 || output.Length > 8192)
                return null;
            foreach (string line in output.Split('\n'))
            {
                string address = line.Trim().Split(' ',
                    StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                if (IPAddress.TryParse(address, out IPAddress? ip) &&
                    ip.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(ip))
                    return ip;
            }
            return null;
        }
        finally
        {
            child.Stop(); // Job closes for normal and failed query.
        }
    }

    private static async Task<Probe> ProbeAsync(int socksPort,
        string target, bool numericIp, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(7));
        try
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, socksPort, timeout.Token);
            using var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token);
            byte[] answer = new byte[2];
            await stream.ReadExactlyAsync(answer, timeout.Token);
            if (answer[0] != 5 || answer[1] != 0)
                return new(false, "SOCKS5 握手拒绝");
            byte[] destination;
            if (numericIp)
            {
                if (!IPAddress.TryParse(target, out var ip) ||
                    ip.AddressFamily != AddressFamily.InterNetwork)
                    return new(false, "IPv4 格式无效");
                destination = new byte[] { 5, 1, 0, 1 }
                    .Concat(ip.GetAddressBytes()).Concat(new byte[] { 1, 187 })
                    .ToArray();
            }
            else
            {
                byte[] hostname = Encoding.ASCII.GetBytes(target);
                if (hostname.Length is <= 0 or > 255)
                    return new(false, "主机名格式无效");
                destination = new byte[] { 5, 1, 0, 3, (byte)hostname.Length }
                    .Concat(hostname).Concat(new byte[] { 1, 187 }).ToArray();
            }
            await stream.WriteAsync(destination, timeout.Token);
            byte[] reply = new byte[4];
            await stream.ReadExactlyAsync(reply, timeout.Token);
            if (reply[0] != 5 || reply[2] != 0)
                return new(false, "SOCKS5 响应无效");
            if (reply[1] != 0)
                return new(false, "SOCKS5 CONNECT 拒绝（代码 " +
                    reply[1].ToString(System.Globalization.CultureInfo.InvariantCulture) + "）");
            // Consume BND.ADDR/BND.PORT to ensure it is a complete response.
            int addressSize;
            if (reply[3] == 1) addressSize = 4;
            else if (reply[3] == 4) addressSize = 16;
            else if (reply[3] == 3)
            {
                byte[] len = new byte[1];
                await stream.ReadExactlyAsync(len, timeout.Token);
                addressSize = len[0];
            }
            else return new(false, "SOCKS5 地址类型无效");
            byte[] trailing = new byte[addressSize + 2];
            await stream.ReadExactlyAsync(trailing, timeout.Token);
            return new(true, "SOCKS5 TCP CONNECT 成功");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new(false, "7 秒内 SOCKS5 TCP CONNECT 超时");
        }
        catch (IOException)
        {
            return new(false, "SOCKS5 连接被关闭");
        }
        catch (SocketException)
        {
            return new(false, "本地代理不可用或转发失败");
        }
    }

    internal static async Task<Result> CompareAsync(SshInput.Validated options,
        CancellationToken cancellationToken)
    {
        // This remains a *diagnosis*, no actual traffic routing override.
        // Oracle resolution runs as a separate read-only SSH command and
        // refuses unknown host keys / unsafe credentials.
        Probe[] nameProbes = new Probe[2];
        for (int i = 0; i < nameProbes.Length; i++)
            nameProbes[i] = await ProbeAsync(10880, Destination, false, cancellationToken);
        IPAddress? oracleIpv4 = await GetOracleARecordAsync(options, cancellationToken);
        if (oracleIpv4 is null)
            return new(false,
                "域名 SOCKS CONNECT 成功 " + nameProbes.Count(p => p.Succeeded) +
                "/2；Oracle 只读 A 记录查询失败，无法比较指定 IPv4。");
        Probe[] ipv4Probes = new Probe[2];
        for (int i = 0; i < ipv4Probes.Length; i++)
            ipv4Probes[i] = await ProbeAsync(
                10880, oracleIpv4.ToString(), true, cancellationToken);

        int hostnameOk = nameProbes.Count(p => p.Succeeded);
        int ipv4Ok = ipv4Probes.Count(p => p.Succeeded);
        string detail = "Google TCP CONNECT 对比：域名 " + hostnameOk +
            "/2；Oracle 解析的 IPv4 " + oracleIpv4 + " " + ipv4Ok + "/2。";
        if (hostnameOk < ipv4Ok)
            return new(true, detail +
                " 地址族/远端 DNS 选择值得继续调查，但尚未证明 SSH 选用了 IPv6。");
        if (hostnameOk == 2 && ipv4Ok == 2)
            return new(true, detail +
                " 两种 TCP 连接均成功；Gmail HTTPS/浏览器加载仍需另外测试。");
        return new(true, detail +
            " 未发现单纯使用 IPv4 有稳定优势，继续检查 SSH 和实际 TLS/HTTPS。");
    }

    // CI only. Fake localhost SOCKS5 peer and no remote network traffic.
    internal static async Task<bool> SelfTestAsync()
    {
        foreach (bool numeric in new[] { false, true })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task<bool> fake = Task.Run(async () =>
                {
                    using var socket = await listener.AcceptTcpClientAsync(timeout.Token);
                    var stream = socket.GetStream();
                    var greeting = new byte[3];
                    await stream.ReadExactlyAsync(greeting, timeout.Token);
                    if (!greeting.AsSpan().SequenceEqual(new byte[] { 5, 1, 0 }))
                        return false;
                    await stream.WriteAsync(new byte[] { 5, 0 }, timeout.Token);
                    byte[] header = new byte[4];
                    await stream.ReadExactlyAsync(header, timeout.Token);
                    if (header[0] != 5 || header[1] != 1 || header[2] != 0 ||
                        header[3] != (numeric ? 1 : 3)) return false;
                    byte[] hostnameOrAddress;
                    if (numeric) hostnameOrAddress = new byte[4];
                    else
                    {
                        byte[] length = new byte[1];
                        await stream.ReadExactlyAsync(length, timeout.Token);
                        hostnameOrAddress = new byte[length[0]];
                    }
                    await stream.ReadExactlyAsync(hostnameOrAddress, timeout.Token);
                    byte[] targetPort = new byte[2];
                    await stream.ReadExactlyAsync(targetPort, timeout.Token);
                    if (targetPort[0] != 1 || targetPort[1] != 187) return false;
                    // Return a valid SOCKS success response; no TCP forwarding.
                    await stream.WriteAsync(
                        new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 },
                        timeout.Token);
                    return numeric
                        ? IPAddress.Parse("203.0.113.7").GetAddressBytes()
                            .SequenceEqual(hostnameOrAddress)
                        : Encoding.ASCII.GetString(hostnameOrAddress) == Destination;
                }, timeout.Token);
                Probe probe = await ProbeAsync(port,
                    numeric ? "203.0.113.7" : Destination, numeric, timeout.Token);
                bool valid = await fake.WaitAsync(timeout.Token);
                if (!probe.Succeeded || !valid) return false;
            }
            finally { listener.Stop(); }
        }
        Console.WriteLine("R58_SOCKS5_A_RECORD_VS_DOMAIN_LOOPBACK_PROTOCOL_PASS");
        return true;
    }
}
