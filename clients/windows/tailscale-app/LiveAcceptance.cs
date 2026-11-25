using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.Tailscale;

/// <summary>Hosted acceptance for the packaged client using the same connection path as the UI.</summary>
internal static partial class LiveAcceptance
{
    private const string Username = "ORACLE_CLIENT_ACCEPTANCE_USERNAME";
    private const string Password = "ORACLE_CLIENT_ACCEPTANCE_PASSWORD";
    private const string Trace = "https://1.1.1.1/cdn-cgi/trace";
    private const string Speed = "https://speed.cloudflare.com/";
    private const int TransferBytes = 10 * 1024 * 1024;
    private const int ParallelStreams = 4;

    internal static async Task<int> Run(string output)
    {
        string? username = Environment.GetEnvironmentVariable(Username);
        string? password = Environment.GetEnvironmentVariable(Password);
        Environment.SetEnvironmentVariable(Username, null);
        Environment.SetEnvironmentVariable(Password, null);
        string phase = "START";
        var report = new Dictionary<string, object?>();
        using var account = new AccountClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        string? session = null;
        int result = 1;
        DaemonProcess? retained = null;
        ExitProfile? previous = null;
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
            int warmReconnects = 0;
            for (int run = 0; run < 3; run++)
            {
                phase = run == 0 ? "FIRST_CONNECT" : "RECONNECT";
                var startedAt = DateTimeOffset.UtcNow;
                var timer = Stopwatch.StartNew();
                string attempt = phase;
                var timing = new ConcurrentDictionary<string, long>();
                report["last_connection_milestones_ms"] = timing;
                var supplied = retained;
                retained = null;
                var (daemon, profile) = await ClientConnection.Open(account, session, state, timeout.Token,
                    stage => phase = attempt + "_" + stage, (stage, elapsed) => timing[stage] = elapsed,
                    retained: supplied, previous: previous);
                bool reused = ReferenceEquals(supplied, daemon);
                if (reused) warmReconnects++;
                previous = profile;
                long connectedMs = timer.ElapsedMilliseconds;
                string initialTransport;
                string transport;
                try
                {
                    if (run == 0) report["account_rate_limited"] = profile.RateLimited;
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
                    initialTransport = await daemon.Control.ReadExitTransport(profile.NodeId, timeout.Token);
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
                    phase = "DISCONNECT";
                    if (run < 2 && await ClientConnection.TryRestoreDirect(daemon, timeout.Token))
                        retained = daemon;
                }
                finally
                {
                    var stop = Stopwatch.StartNew();
                    if (retained is null)
                    {
                        try { await daemon.DisposeAsync(); }
                        catch { phase = "DISCONNECT_ENGINE"; throw; }
                    }
                    timing["disconnect_engine_duration"] = stop.ElapsedMilliseconds;
                }

                phase = "RESTORE_DIRECT";
                var restoring = Stopwatch.StartNew();
                var restored = await ObserveIPv4(web, timeout.Token);
                await Dns.GetHostAddressesAsync("speed.cloudflare.com", timeout.Token);
                if (!restored.Equals(direct)) throw new IOException("DIRECT_ROUTE_NOT_RESTORED");
                connections.Add(new
                {
                    started_at = startedAt,
                    connect_ms = connectedMs, reused_coordinator = reused, initial_transport = initialTransport, transport,
                    milestones_ms = timing,
                    direct_route_confirmation_ms = restoring.ElapsedMilliseconds,
                });
            }
            phase = "VERIFY_FAST_RECONNECT";
            if (warmReconnects == 0) throw new IOException("WARM_RECONNECT_NOT_OBSERVED");
            report["warm_reconnects"] = warmReconnects;
            report.Remove("last_connection_milestones_ms");
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
            if (retained is not null)
            {
                try { await retained.DisposeAsync(); }
                catch
                {
                    report["retained_cleanup_failed"] = true;
                    result = 1;
                }
            }
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
        using var single = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        single.CancelAfter(TimeSpan.FromSeconds(30));
        var downloadStartedAt = DateTimeOffset.UtcNow;
        var timer = Stopwatch.StartNew();
        await Download(web, TransferBytes, single.Token);
        double download = Rate(TransferBytes, timer.Elapsed);
        var downloadEndedAt = DateTimeOffset.UtcNow;
        single.CancelAfter(TimeSpan.FromSeconds(30));
        var uploadStartedAt = DateTimeOffset.UtcNow;
        timer.Restart();
        await Upload(web, TransferBytes, single.Token);
        double upload = Rate(TransferBytes, timer.Elapsed);
        var uploadEndedAt = DateTimeOffset.UtcNow;
        const int downloadPerStream = 8 * 1024 * 1024;
        const int uploadPerStream = 4 * 1024 * 1024;
        var multiDownload = await Aggregate(web, downloadPerStream, Download, cancel);
        var multiUpload = await Aggregate(web, uploadPerStream, Upload, cancel);
        await RequireIPv4(web, expected, cancel);
        return new
        {
            bytes_each_direction = TransferBytes,
            download_mbps = download,
            download_started_at = downloadStartedAt,
            download_ended_at = downloadEndedAt,
            upload_mbps = upload,
            upload_started_at = uploadStartedAt,
            upload_ended_at = uploadEndedAt,
            https_p50_ms = Math.Round((latencies[4] + latencies[5]) / 2, 2),
            https_p95_ms = Math.Round(latencies[9], 2),
            aggregate = new { parallel_streams = ParallelStreams, download = multiDownload, upload = multiUpload },
        };
    }

    private static async Task Download(HttpClient web, int bytes, CancellationToken cancel)
    {
        using var get = await web.GetAsync(Speed + "__down?bytes=" + bytes, HttpCompletionOption.ResponseHeadersRead, cancel);
        get.EnsureSuccessStatusCode();
        await using var body = await get.Content.ReadAsStreamAsync(cancel);
        byte[] buffer = new byte[32_768];
        int received = 0, block;
        while ((block = await body.ReadAsync(buffer, cancel)) != 0)
        {
            received += block;
            if (received > bytes) throw new IOException("SPEED_DOWNLOAD_LENGTH_MISMATCH");
        }
        if (received != bytes) throw new IOException("SPEED_DOWNLOAD_LENGTH_MISMATCH");
    }

    private static async Task Upload(HttpClient web, int bytes, CancellationToken cancel)
    {
        using var post = new ByteArrayContent(new byte[bytes]);
        using var upload = await web.PostAsync(Speed + "__up", post, cancel);
        upload.EnsureSuccessStatusCode();
    }

    private static async Task<object> Aggregate(HttpClient web, int bytesPerStream,
        Func<HttpClient, int, CancellationToken, Task> transfer, CancellationToken cancel)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(30));
        var startedAt = DateTimeOffset.UtcNow;
        var timer = Stopwatch.StartNew();
        int bytes = bytesPerStream * ParallelStreams;
        bool completed = false;
        var tasks = Enumerable.Range(0, ParallelStreams).Select(_ => transfer(web, bytesPerStream, limit.Token)).ToArray();
        try
        {
            await Task.WhenAll(tasks);
            completed = true;
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested) { }
        long finished = tasks.LongCount(task => task.IsCompletedSuccessfully) * bytesPerStream;
        return new
        {
            target_bytes = bytes,
            completed_bytes = finished,
            started_at = startedAt,
            ended_at = DateTimeOffset.UtcNow,
            throughput_mbps = completed ? (double?)Rate(bytes, timer.Elapsed) : null,
            elapsed_ms = timer.ElapsedMilliseconds,
            status = completed ? "completed" : "timeout",
        };
    }

    private static double Rate(int bytes, TimeSpan elapsed) =>
        Math.Round(8.0 * bytes / elapsed.TotalSeconds / 1_000_000, 2);

    private static async Task RequireIPv4(HttpClient web, IPAddress expected, CancellationToken cancel)
    {
        if (!(await ObserveIPv4(web, cancel)).Equals(expected)) throw new IOException("UNEXPECTED_SYSTEM_EGRESS");
    }

    private static Task<IPAddress> ObserveIPv4(HttpClient web, CancellationToken cancel) =>
        ObserveIP(web, Trace, cancel);

    private static async Task<IPAddress> ObserveIP(HttpClient web, string endpoint, CancellationToken cancel)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.ConnectionClose = true;
        using var response = await web.SendAsync(request, cancel);
        response.EnsureSuccessStatusCode();
        string body = await response.Content.ReadAsStringAsync(cancel);
        var ip = body.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
        return ip is not null && IPAddress.TryParse(ip[3..].Trim(), out var address)
            ? address : throw new IOException("TRACE_RESPONSE_MISSING_IP");
    }
}
