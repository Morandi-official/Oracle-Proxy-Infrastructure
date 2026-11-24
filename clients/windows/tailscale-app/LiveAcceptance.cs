using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.Tailscale;

/// <summary>Hosted acceptance for the packaged client using the same connection path as the UI.</summary>
internal static class LiveAcceptance
{
    private const string Username = "ORACLE_CLIENT_ACCEPTANCE_USERNAME";
    private const string Password = "ORACLE_CLIENT_ACCEPTANCE_PASSWORD";
    private const string Trace = "https://1.1.1.1/cdn-cgi/trace";
    private const string Speed = "https://speed.cloudflare.com/";
    private const int TransferBytes = 10 * 1024 * 1024;

    internal static async Task<int> Run(string output)
    {
        string? username = Environment.GetEnvironmentVariable(Username);
        string? password = Environment.GetEnvironmentVariable(Password);
        Environment.SetEnvironmentVariable(Username, null);
        Environment.SetEnvironmentVariable(Password, null);
        string phase = "START";
        var report = new Dictionary<string, object>();
        using var account = new AccountClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        string? session = null;
        int result = 1;
        try
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
                throw new IOException("ACCEPTANCE_CREDENTIALS_MISSING");

            phase = "BASELINE";
            string state = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, "state");
            using var web = new HttpClient(new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromSeconds(8),
                PooledConnectionLifetime = TimeSpan.FromSeconds(3),
            }) { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 8192 };
            var direct = await ObserveIPv4(web, timeout.Token);
            report["baseline"] = await Performance(web, direct, timeout.Token);

            phase = "LOGIN";
            session = await account.Login(username, password, ClientConnection.Device(state), timeout.Token);
            password = null;

            var connections = new List<object>();
            report["connections"] = connections;
            for (int run = 0; run < 3; run++)
            {
                phase = run == 0 ? "FIRST_CONNECT" : "RECONNECT";
                var timer = Stopwatch.StartNew();
                string attempt = phase;
                var (daemon, profile) = await ClientConnection.Open(account, session, state, timeout.Token,
                    stage => phase = attempt + "_" + stage);
                long connectedMs = timer.ElapsedMilliseconds;
                string transport;
                try
                {
                    phase = "VERIFY_SYSTEM_ROUTE";
                    // The caller uses ordinary system routing. The product has
                    // also verified both IP families through its own adapter.
                    var expected = IPAddress.Parse(profile.IPv4);
                    if (expected.Equals(direct))
                        throw new IOException("ACCEPTANCE_BASELINE_EQUALS_EXIT");
                    using var tunneled = new HttpClient(new SocketsHttpHandler
                    {
                        UseProxy = false,
                        AllowAutoRedirect = false,
                        ConnectTimeout = TimeSpan.FromSeconds(8),
                    }) { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 8192 };
                    await RequireIPv4(tunneled, expected, timeout.Token);
                    if (run == 0)
                    {
                        phase = "TUNNEL_PERFORMANCE";
                        report["tunnel"] = await Performance(tunneled, expected, timeout.Token);
                        phase = "TUNNEL_STABILITY";
                        for (int sample = 0; sample < 10; sample++)
                        {
                            await Task.Delay(TimeSpan.FromSeconds(2), timeout.Token);
                            await RequireIPv4(tunneled, expected, timeout.Token);
                        }
                        report["stability"] = new { samples = 10, interval_ms = 2000, failures = 0 };
                    }
                    transport = await daemon.Control.ReadExitTransport(profile.NodeId, timeout.Token);
                }
                finally { await daemon.DisposeAsync(); }

                phase = "RESTORE_DIRECT";
                var restored = await ObserveIPv4(web, timeout.Token);
                if (!restored.Equals(direct)) throw new IOException("DIRECT_ROUTE_NOT_RESTORED");
                connections.Add(new { connect_ms = connectedMs, transport });
            }
            result = 0;
        }
        catch (Exception error)
        {
            report["phase"] = phase;
            report["error"] = error is IOException && Regex.IsMatch(error.Message, @"\A[A-Z0-9_]{1,80}\z")
                ? error.Message : error.GetType().Name;
        }
        finally
        {
            if (session is not null)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                try { await account.Release(session, cleanup.Token); }
                catch
                {
                    report["device_release_failed"] = true;
                    result = 1;
                }
            }
            report["accepted"] = result == 0;
            File.WriteAllText(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        }
        return result;
    }

    private static async Task<object> Performance(HttpClient web, IPAddress expected, CancellationToken cancel)
    {
        var latencies = new List<double>();
        for (int i = 0; i < 10; i++)
        {
            var sample = Stopwatch.StartNew();
            await RequireIPv4(web, expected, cancel);
            latencies.Add(sample.Elapsed.TotalMilliseconds);
        }
        latencies.Sort();
        var timer = Stopwatch.StartNew();
        using (var get = await web.GetAsync(Speed + "__down?bytes=" + TransferBytes, HttpCompletionOption.ResponseHeadersRead, cancel))
        {
            get.EnsureSuccessStatusCode();
            await using var body = await get.Content.ReadAsStreamAsync(cancel);
            byte[] buffer = new byte[32_768];
            int received = 0, block;
            while ((block = await body.ReadAsync(buffer, cancel)) != 0)
            {
                received += block;
                if (received > TransferBytes) throw new IOException("SPEED_DOWNLOAD_LENGTH_MISMATCH");
            }
            if (received != TransferBytes) throw new IOException("SPEED_DOWNLOAD_LENGTH_MISMATCH");
        }
        double download = Rate(timer.Elapsed);
        timer.Restart();
        using var post = new ByteArrayContent(new byte[TransferBytes]);
        using var upload = await web.PostAsync(Speed + "__up", post, cancel);
        upload.EnsureSuccessStatusCode();
        return new
        {
            bytes_each_direction = TransferBytes,
            download_mbps = download,
            upload_mbps = Rate(timer.Elapsed),
            https_p50_ms = Math.Round((latencies[4] + latencies[5]) / 2, 2),
            https_p95_ms = Math.Round(latencies[9], 2),
        };
    }

    private static double Rate(TimeSpan elapsed) => Math.Round(8.0 * TransferBytes / elapsed.TotalSeconds / 1_000_000, 2);

    private static async Task RequireIPv4(HttpClient web, IPAddress expected, CancellationToken cancel)
    {
        if (!(await ObserveIPv4(web, cancel)).Equals(expected)) throw new IOException("UNEXPECTED_SYSTEM_EGRESS");
    }

    private static async Task<IPAddress> ObserveIPv4(HttpClient web, CancellationToken cancel)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Trace);
        request.Headers.ConnectionClose = true;
        using var response = await web.SendAsync(request, cancel);
        response.EnsureSuccessStatusCode();
        string body = await response.Content.ReadAsStringAsync(cancel);
        var ip = body.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
        return ip is not null && IPAddress.TryParse(ip[3..].Trim(), out var address)
            ? address : throw new IOException("TRACE_RESPONSE_MISSING_IP");
    }
}
