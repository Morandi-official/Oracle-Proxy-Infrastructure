using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using OracleProxy.Product;

const string host = "speed.cloudflare.com";
const string traceHost = "www.cloudflare.com";
const string exitIPv4 = "152.67.156.100";
const int limit = 2 * 1024 * 1024;
const int latencySamples = 20;

if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
    Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
    Environment.GetEnvironmentVariable("GITHUB_REF") != "refs/heads/main") return 2;

var username = Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME");
var password = Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return 2;

async Task<JsonObject> Request(string command, string? first = null, string? second = null)
{
    var response = await ControlPipe.Send(command, first, second).WaitAsync(TimeSpan.FromSeconds(20));
    if (response["ok"]?.GetValue<bool>() != true)
        throw new IOException(command + "_" + response["error"]?.GetValue<string>());
    return response;
}

async Task<IPAddress[]> Resolve(string mode, string target = host)
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var sw = Stopwatch.StartNew();
    try {
        var addresses = await Dns.GetHostAddressesAsync(target, deadline.Token);
        Console.WriteLine("WINDOWS_BULK_DNS=" + JsonSerializer.Serialize(new {
            mode, ipv4 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetwork),
            ipv6 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetworkV6), ms = sw.ElapsedMilliseconds
        }));
        return addresses;
    } catch (Exception exception) when (exception is SocketException or OperationCanceledException) {
        Console.WriteLine("WINDOWS_BULK_DNS=" + JsonSerializer.Serialize(new {
            mode, error = exception.GetType().Name, ms = sw.ElapsedMilliseconds
        }));
        return [];
    }
}

async Task Download(string route, IPAddress? pinned)
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12));
    using var handler = new SocketsHttpHandler {
        UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
    };
    long? tcpMs = null, headersMs = null, firstDataMs = null, lastDataMs = null, contentLength = null;
    int bytes = 0, status = 0;
    string error = "", httpError = "";
    var sw = Stopwatch.StartNew();
    if (pinned is not null) {
        handler.ConnectCallback = async (context, token) => {
            if (context.DnsEndPoint.Host != host || context.DnsEndPoint.Port != 443)
                throw new IOException("UNEXPECTED_SPEED_ORIGIN");
            var socket = new Socket(pinned.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try {
                await socket.ConnectAsync(new IPEndPoint(pinned, 443), token);
                tcpMs = sw.ElapsedMilliseconds;
                return new NetworkStream(socket, ownsSocket: true);
            } catch {
                socket.Dispose();
                throw;
            }
        };
    }
    using var client = new HttpClient(handler);
    try {
        using var result = await client.GetAsync($"https://{host}/__down?bytes={limit}",
            HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        headersMs = sw.ElapsedMilliseconds;
        status = (int)result.StatusCode;
        contentLength = result.Content.Headers.ContentLength;
        result.EnsureSuccessStatusCode();
        await using var stream = await result.Content.ReadAsStreamAsync(deadline.Token);
        byte[] buffer = new byte[32768];
        while (bytes <= limit) {
            int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(limit + 1 - bytes, buffer.Length)), deadline.Token);
            if (read == 0) break;
            firstDataMs ??= sw.ElapsedMilliseconds;
            lastDataMs = sw.ElapsedMilliseconds;
            bytes += read;
        }
    } catch (Exception failure) when (failure is HttpRequestException or IOException or OperationCanceledException) {
        error = failure.GetType().Name;
        if (failure is HttpRequestException http) httpError = http.HttpRequestError.ToString();
    }
    Console.WriteLine("WINDOWS_BULK_DOWNLOAD=" + JsonSerializer.Serialize(new {
        route, family = pinned?.AddressFamily.ToString() ?? "automatic", tcpMs,
        headersMs, firstDataMs, lastDataMs, bytes, contentLength, status, error, httpError, totalMs = sw.ElapsedMilliseconds,
    }));
}

async Task<string> MeasureLatency(string route, IPAddress pinned, bool fresh, string? expected)
{
    int sockets = 0;
    using var handler = new SocketsHttpHandler
    {
        UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
        ConnectCallback = async (context, cancel) =>
        {
            if (context.DnsEndPoint.Host != traceHost || context.DnsEndPoint.Port != 443)
                throw new IOException("UNEXPECTED_HTTPS_ORIGIN");
            Interlocked.Increment(ref sockets);
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(pinned, 443), cancel);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        },
    };
    using var client = new HttpClient(handler);

    async Task<(double ms, string ip)> Sample()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{traceHost}/cdn-cgi/trace")
        {
            Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Headers.ConnectionClose = fresh;
        var time = Stopwatch.StartNew();
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        byte[] data = new byte[8192];
        int count = await stream.ReadAsync(data, deadline.Token);
        double firstByte = time.Elapsed.TotalMilliseconds;
        while (count > 0 && count < data.Length)
        {
            int more = await stream.ReadAsync(data.AsMemory(count), deadline.Token);
            if (more == 0) break;
            count += more;
        }
        if (count == 0 || count == data.Length) throw new IOException("INVALID_HTTPS_PROBE_SIZE");
        string? ip = System.Text.Encoding.ASCII.GetString(data, 0, count).Split('\n')
            .FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal))?[3..].Trim();
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork ||
            (expected is null ? ip == exitIPv4 : ip != expected)) throw new IOException("HTTPS_PROBE_EGRESS_MISMATCH");
        return (firstByte, address.ToString());
    }

    // Bootstrap identity independently of the 20 measured requests. Reused samples
    // count only if the original authenticated connection remains in the pool.
    expected ??= (await Sample()).ip;
    if (!fresh && sockets == 0) await Sample();
    int initialSockets = sockets;
    int failures = 0;
    var observed = new List<double>(latencySamples);
    for (int i = 0; i < latencySamples; i++)
    {
        int before = sockets;
        try
        {
            var sample = await Sample();
            if (fresh ? sockets != before + 1 : sockets != initialSockets) failures++;
            else observed.Add(Math.Round(sample.ms, 2));
        }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException or IOException)
        { failures++; }
    }
    var ordered = observed.Order().ToArray();
    Console.WriteLine("WIREGUARD_BASELINE_HTTPS=" + JsonSerializer.Serialize(new
    {
        route, target = traceHost + "/cdn-cgi/trace", protocol = "HTTP/1.1", family = 4,
        fresh, requested = latencySamples, successful = observed.Count, failures,
        p95_ms = ordered.Length == 0 ? (double?)null : ordered[(int)Math.Ceiling(ordered.Length * .95) - 1],
        max_ms = ordered.Length == 0 ? (double?)null : ordered[^1], samples_ms = observed,
    }));
    return expected;
}

string? device = null;
try {
    await Request("AttachClient");
    var loginTimer = Stopwatch.StartNew();
    var account = await Request("Login", username, password);
    device = account["registration"]?["device_id"]?.GetValue<string>();
    if (account["device_registered"]?.GetValue<bool>() != true ||
        device?.Length != 12 || device.Any(c => !Uri.IsHexDigit(c))) throw new IOException("TEST_DEVICE_MISSING");
    Console.WriteLine("WIREGUARD_BASELINE_FRESH_LOGIN_MS=" + loginTimer.ElapsedMilliseconds);
    var traceAddress = (await Resolve("trace-ipv4", traceHost)).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
        ?? throw new IOException("WINDOWS_TRACE_IPV4_UNAVAILABLE");
    string directExit = await MeasureLatency("direct", traceAddress, fresh: true, expected: null);
    await MeasureLatency("direct", traceAddress, fresh: false, expected: directExit);
    var destinations = await Resolve("direct");
    var ipv4 = destinations.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
    var ipv6 = destinations.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
    await Download("direct", null);
    if (ipv4 is not null) await Download("direct", ipv4);
    var connectionTimer = Stopwatch.StartNew();
    await Request("Connect");
    for (int n = 0; n < 40; n++) {
        var state = await Request("Status");
        if (state["mode"]?.GetValue<string>() == "connected" && state["verified_exit_ip"]?.GetValue<string>() == exitIPv4 &&
            !string.IsNullOrEmpty(state["verified_exit_ipv6"]?.GetValue<string>()))
        {
            Console.WriteLine("WIREGUARD_BASELINE_CONNECTION=" + JsonSerializer.Serialize(new
            {
                command_to_egress_ms = connectionTimer.ElapsedMilliseconds,
                service_click_to_ready_ms = state["click_to_ready_ms"],
                port = state["native_udp_selected_port"],
            }));
            break;
        }
        if (n == 39) throw new IOException("WINDOWS_TUNNEL_NOT_VERIFIED");
        await Task.Delay(250);
    }
    await MeasureLatency("wireguard", traceAddress, fresh: true, expected: exitIPv4);
    await MeasureLatency("wireguard", traceAddress, fresh: false, expected: exitIPv4);
    await Resolve("wireguard");
    await Download("wireguard", null);
    if (ipv4 is not null) await Download("wireguard", ipv4);
    if (ipv6 is not null) await Download("wireguard", ipv6);
    return 0;
} finally {
    if (device?.Length == 12 && device.All(Uri.IsHexDigit)) {
        await Request("Disconnect");
        await ControlPipe.WaitStopped(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(15));
        await Request("AttachClient");
        await Request("DeleteDevice", device);
        Console.WriteLine("WINDOWS_BULK_TEST_DEVICE_REMOVED=PASS");
    }
}
