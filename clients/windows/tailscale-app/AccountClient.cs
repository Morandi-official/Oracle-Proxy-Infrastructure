using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;

namespace OracleProxy.Tailscale;

internal sealed class AccountClient : IDisposable
{
    private static readonly TimeSpan AlternateDeadline = TimeSpan.FromSeconds(22);
    private static readonly Uri Address = new("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/");
    private static readonly HttpClient EncryptedDns = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(8),
        MaxResponseContentBufferSize = 8192,
    };
    private Task<AccountRoute?>? _preparation;
    private Task<WindowsProxySetting?>? _windowsProxy;
    private long _preparationStarted;
    private AccountRoute? _active;

    internal Version? ResponseVersion { get; private set; }
    internal string? LoginRoute => _active?.Kind;

    private sealed record WindowsProxySetting(IWebProxy Handler, Uri? CoordinatorProxy);

    private sealed class AccountRoute(string kind, IWebProxy? proxy, Version version, HttpVersionPolicy policy,
        IPAddress? address = null, Uri? coordinatorProxy = null) : IDisposable
    {
        internal string Kind { get; } = kind;
        internal Version Version { get; } = version;
        internal HttpVersionPolicy Policy { get; } = policy;
        internal IPAddress? AddressProof { get; } = address;
        internal Uri? CoordinatorProxy { get; } = coordinatorProxy;
        internal long LastResponse = Stopwatch.GetTimestamp();

        internal HttpClient Http { get; } = new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = proxy is not null,
            Proxy = proxy,
            ConnectTimeout = kind == "direct" ? TimeSpan.FromSeconds(5) : AlternateDeadline,
            KeepAlivePingDelay = TimeSpan.FromSeconds(10),
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always,
        })
        {
            BaseAddress = address is null ? Address : new UriBuilder(Address) { Host = address.ToString() }.Uri,
            Timeout = kind == "direct" ? TimeSpan.FromSeconds(12) : AlternateDeadline,
            MaxResponseContentBufferSize = 16_384,
        };

        public void Dispose() => Http.Dispose();
    }

    internal async Task<string?> PrepareLogin(CancellationToken cancel)
    {
        if (_preparation is { IsCompleted: true } prior &&
            (Stopwatch.GetElapsedTime(_preparationStarted) > TimeSpan.FromSeconds(45) ||
             prior.IsCompletedSuccessfully && prior.Result is null))
        {
            _preparation = null;
            _ = DisposeWhenReady(prior);
        }
        if (_preparation is null)
        {
            _preparationStarted = Stopwatch.GetTimestamp();
            _preparation = FindLoginRoute(cancel);
        }
        return (await _preparation)?.Kind;
    }

    internal async Task<string> Login(string username, string password, string device, CancellationToken cancel,
        Action? tryingAlternate = null)
    {
        var preparation = _preparation;
        _preparation = null;
        if (preparation is not null && Stopwatch.GetElapsedTime(_preparationStarted) > TimeSpan.FromSeconds(45))
        {
            _ = DisposeWhenReady(preparation);
            preparation = null;
        }
        _active?.Dispose();
        _active = null;

        var route = preparation is null ? null : await preparation;
        if (route is null)
        {
            tryingAlternate?.Invoke();
            route = await FindLoginRoute(cancel);
        }
        if (route is null) throw new IOException("ACCOUNT_ROUTE_TIMEOUT");

        _active = route;
        using var result = await PostWithRouteRecovery("login", null, new { username, password, device }, cancel,
            tryingAlternate);
        return ReadToken(result);
    }

    private static bool CanTryAnotherRoute(IOException error) => error.Message is
        "ACCOUNT_DNS_FAILED" or "ACCOUNT_CONNECT_FAILED" or "ACCOUNT_TIMEOUT" or "ACCOUNT_HTTP_FAILED"
        or "ACCOUNT_PROXY_FAILED" or "ACCOUNT_TLS_FAILED";

    private async Task<JsonDocument> PostWithRouteRecovery(string action, string? token, object value,
        CancellationToken cancel, Action? tryingAlternate = null)
    {
        var route = _active ?? throw new IOException("LOGIN_REQUIRED");
        try
        {
            return await Post(action, token, value, cancel, route);
        }
        catch (IOException error) when (!cancel.IsCancellationRequested && CanTryAnotherRoute(error))
        {
            tryingAlternate?.Invoke();
            // Verify a replacement without credentials. Only replay after the
            // first request has ended. The server reconciles interrupted enrollment.
            var replacement = await FindLoginRoute(cancel, route.Kind)
                ?? throw new IOException("ACCOUNT_ROUTE_TIMEOUT", error);
            _active = replacement;
            route.Dispose();
            return await Post(action, token, value, cancel, replacement);
        }
    }

    internal CoordinatorRouteHint CoordinatorRoute => _active switch
    {
        { Kind: "system-proxy", CoordinatorProxy: { } proxy } =>
            new(Address.IdnHost, null, proxy, Direct: false),
        { Kind: "system-proxy" } or null =>
            new(Address.IdnHost, null, null, Direct: false),
        var route => new(Address.IdnHost, route.AddressProof, null, Direct: true,
            FallbackProxy: _windowsProxy is { IsCompletedSuccessfully: true } resolved
                ? resolved.Result?.CoordinatorProxy : null),
    };

    private async Task<AccountRoute?> FindLoginRoute(CancellationToken cancel, string? previous = null)
    {
        var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(AlternateDeadline);
        // Proxy discovery also serves the native TCP coordinator. An account
        // probe over QUIC can win without proving that its TCP route works.
        var windowsProxy = _windowsProxy = ResolveWindowsProxy();
        var addresses = TryResolveAccountAddress(limit.Token);
        var pending = new List<Task<AccountRoute?>>
        {
            TryRoute(new("direct", null, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower), limit.Token, previous),
            TryEncryptedDns(addresses, http3: false, limit.Token, previous),
            TryWindowsProxy(windowsProxy, limit.Token, previous),
            TryRoute(new("http1", null, HttpVersion.Version11, HttpVersionPolicy.RequestVersionExact), limit.Token, previous),
        };
        if (System.Net.Quic.QuicConnection.IsSupported)
            pending.Add(TryEncryptedDns(addresses, http3: true, limit.Token, previous));
        AccountRoute? selected = null;
        try
        {
            while (pending.Count > 0 && selected is null)
            {
                var next = await Task.WhenAny(pending);
                pending.Remove(next);
                selected = await next;
            }
            return selected;
        }
        catch
        {
            selected?.Dispose();
            throw;
        }
        finally
        {
            _ = CancelUnusedRoutes(limit, pending);
        }
    }

    private static async Task CancelUnusedRoutes(CancellationTokenSource limit, List<Task<AccountRoute?>> pending)
    {
        using (limit)
        {
            try { await limit.CancelAsync().ConfigureAwait(false); }
            finally { await Task.WhenAll(pending.Select(DisposeWhenReady)).ConfigureAwait(false); }
        }
    }

    private static async Task<WindowsProxySetting?> ResolveWindowsProxy()
    {
        try
        {
            var proxy = HttpClient.DefaultProxy;
            var endpoint = await Task.Run(() => proxy.GetProxy(Address)).WaitAsync(TimeSpan.FromSeconds(3));
            if (endpoint is null || endpoint == Address || !endpoint.IsAbsoluteUri) return null;
            var coordinatorProxy = endpoint.Scheme is "http" or "https" && endpoint.UserInfo.Length == 0 &&
                endpoint.PathAndQuery == "/" && endpoint.Fragment.Length == 0 && proxy.Credentials is null
                ? endpoint : null;
            return new(new WebProxy(endpoint) { Credentials = proxy.Credentials }, coordinatorProxy);
        }
        catch (Exception error) when (error is TimeoutException or OperationCanceledException or
            HttpRequestException or IOException or ArgumentException)
        {
            return null;
        }
    }

    private async Task<AccountRoute?> TryWindowsProxy(Task<WindowsProxySetting?> discovery, CancellationToken cancel,
        string? previous)
    {
        try
        {
            var proxy = await discovery.WaitAsync(cancel);
            if (proxy is null) return null;
            return await TryRoute(new("system-proxy", proxy.Handler, HttpVersion.Version20,
                HttpVersionPolicy.RequestVersionOrLower, coordinatorProxy: proxy.CoordinatorProxy), cancel, previous);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private async Task<AccountRoute?> TryRoute(AccountRoute route, CancellationToken cancel, string? previous = null)
    {
        // This native API check has no secret and is rejected before the login rate limit.
        bool verified = false;
        try
        {
            if (route.Kind == previous) await Task.Delay(250, cancel);
            var probe = new { username = "proxy-route-check", password = "", device = new string('0', 64) };
            using var response = await Post("login", null, probe, cancel, route, recordProtocol: false);
            return null;
        }
        catch (IOException error) when (error.Message == "INVALID_CREDENTIALS")
        {
            verified = true;
            return route;
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or NotSupportedException)
        {
            return null;
        }
        finally
        {
            if (!verified) route.Dispose();
        }
    }

    private async Task<AccountRoute?> TryEncryptedDns(Task<List<IPAddress>> addresses, bool http3,
        CancellationToken cancel, string? previous = null)
    {
        foreach (var ip in await addresses)
        {
            var route = http3
                ? new AccountRoute("encrypted-dns-http3", null, HttpVersion.Version30, HttpVersionPolicy.RequestVersionExact, ip)
                : new AccountRoute("encrypted-dns-tcp", null, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower, ip);
            if (await TryRoute(route, cancel, previous) is { } verified) return verified;
        }
        return null;
    }

    internal Task VerifyEncryptedDnsLogin(string username, string password, string device, CancellationToken cancel) =>
        VerifyEncryptedDnsLogin(username, password, device, http3: false, cancel);

    internal Task VerifyEncryptedDnsHttp3Login(string username, string password, string device, CancellationToken cancel) =>
        VerifyEncryptedDnsLogin(username, password, device, http3: true, cancel);

    private async Task VerifyEncryptedDnsLogin(string username, string password, string device, bool http3, CancellationToken cancel)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(AlternateDeadline);
        using var route = await TryEncryptedDns(TryResolveAccountAddress(limit.Token), http3, limit.Token)
            ?? throw new IOException(http3 ? "ENCRYPTED_DNS_HTTP3_LOGIN_ROUTE_UNAVAILABLE" : "ENCRYPTED_DNS_LOGIN_ROUTE_UNAVAILABLE");
        using var response = await Post("login", null, new { username, password, device }, limit.Token, route,
            recordProtocol: false);
        _ = ReadToken(response);
    }

    private static async Task<List<IPAddress>> TryResolveAccountAddress(CancellationToken cancel)
    {
        using var probes = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        var pending = new List<Task<List<IPAddress>>>
        {
            ResolveAccountAddress("https://1.1.1.1/dns-query", null, probes.Token),
            ResolveAccountAddress("https://8.8.8.8/resolve", "dns.google", probes.Token),
        };
        while (pending.Count > 0)
        {
            var finished = await Task.WhenAny(pending);
            pending.Remove(finished);
            var addresses = await finished;
            if (addresses.Count == 0) continue;
            probes.Cancel();
            return addresses;
        }
        return [];
    }

    private static async Task<List<IPAddress>> ResolveAccountAddress(string endpoint, string? authority,
        CancellationToken cancel)
    {
        // Only the fixed account hostname is sent to an authenticated resolver.
        using var query = new HttpRequestMessage(HttpMethod.Get,
            endpoint + "?type=A&name=" + Uri.EscapeDataString(Address.IdnHost));
        query.Headers.Host = authority;
        query.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));
        try
        {
            using var reply = await EncryptedDns.SendAsync(query, cancel);
            reply.EnsureSuccessStatusCode();
            using var result = JsonDocument.Parse(await reply.Content.ReadAsByteArrayAsync(cancel));
            if (result.RootElement.ValueKind != JsonValueKind.Object ||
                !result.RootElement.TryGetProperty("Status", out var status) || status.ValueKind != JsonValueKind.Number ||
                !status.TryGetInt32(out int code) || code != 0 ||
                !result.RootElement.TryGetProperty("Answer", out var answers) || answers.ValueKind != JsonValueKind.Array)
                return [];

            var addresses = new List<IPAddress>();
            foreach (var answer in answers.EnumerateArray().Take(8))
            {
                if (answer.ValueKind == JsonValueKind.Object && answer.TryGetProperty("type", out var type) &&
                    type.ValueKind == JsonValueKind.Number && type.TryGetInt32(out int kind) && kind == 1 &&
                    answer.TryGetProperty("data", out var value) && value.ValueKind == JsonValueKind.String &&
                    IPAddress.TryParse(value.GetString(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                    IsPublicAddress(ip))
                    addresses.Add(ip);
            }
            return addresses;
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or OperationCanceledException)
        {
            return [];
        }
    }

    private static bool IsPublicAddress(IPAddress ip)
    {
        byte[] address = ip.GetAddressBytes();
        return address[0] is not (0 or 10 or 127 or >= 224) &&
            !(address[0] == 100 && address[1] is >= 64 and <= 127) &&
            !(address[0] == 169 && address[1] == 254) &&
            !(address[0] == 172 && address[1] is >= 16 and <= 31) &&
            !(address[0] == 192 && address[1] == 168) &&
            !(address[0] == 198 && address[1] is 18 or 19);
    }

    private static string ReadToken(JsonDocument response) =>
        response.RootElement.TryGetProperty("token", out var token) && token.ValueKind == JsonValueKind.String &&
        token.GetString() is { Length: > 0 and <= 2041 } value
            ? value : throw new IOException("ACCOUNT_RESPONSE_INVALID");

    internal async Task WarmActiveRoute(CancellationToken cancel)
    {
        var route = _active;
        if (route is null || Stopwatch.GetElapsedTime(Interlocked.Read(ref route.LastResponse)) < TimeSpan.FromSeconds(15))
            return;

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(3));
        using var probe = new HttpRequestMessage(HttpMethod.Get, "ready")
        {
            Version = route.Version, VersionPolicy = route.Policy,
        };
        if (route.AddressProof is not null) probe.Headers.Host = Address.IdnHost;
        try
        {
            using var response = await route.Http.SendAsync(probe, limit.Token);
            Interlocked.Exchange(ref route.LastResponse, Stopwatch.GetTimestamp());
        }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException or ObjectDisposedException)
        {
            // A failed warm-up cannot replace the authenticated route or its recovery policy.
        }
    }

    internal Task<ExitProfile> Profile(string token, bool confirm, CancellationToken cancel) =>
        ReadProfile(confirm ? "confirm" : "profile", token, cancel);

    internal async Task<ExitProfile> AuthorizeConnection(string token, CancellationToken cancel)
    {
        try { return await Profile(token, false, cancel); }
        catch (IOException error) when (error.Message == "TAILSCALE_ENROLLMENT_PENDING")
        {
            // The previous native attempt has stopped. The server checks
            // this device's unused ticket before it allows a replacement.
            return await ReadProfile("retry-profile", token, cancel);
        }
    }

    private async Task<ExitProfile> ReadProfile(string action, string token, CancellationToken cancel)
    {
        using var response = await PostWithRouteRecovery(action, token, new { }, cancel);
        var data = response.RootElement;
        if (!Uri.TryCreate(ReadProfileString(data, "coordinator"), UriKind.Absolute, out var coordinator) ||
            coordinator.Scheme != Uri.UriSchemeHttps ||
            !long.TryParse(ReadProfileString(data, "exit_node_id"), NumberStyles.None, CultureInfo.InvariantCulture,
                out long nodeId) || nodeId <= 0 ||
            !IPAddress.TryParse(ReadProfileString(data, "ipv4"), out var ipv4) ||
            ipv4.AddressFamily != AddressFamily.InterNetwork ||
            !IPAddress.TryParse(ReadProfileString(data, "ipv6"), out var ipv6) ||
            ipv6.AddressFamily != AddressFamily.InterNetworkV6 ||
            !data.TryGetProperty("enrollment_key", out var key) ||
            key.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            throw new IOException("ACCOUNT_RESPONSE_INVALID");

        bool? rateLimited = data.TryGetProperty("rate_limited", out var limited)
            && limited.ValueKind is JsonValueKind.True or JsonValueKind.False ? limited.GetBoolean() : null;
        return new ExitProfile(coordinator, nodeId, ipv4.ToString(), ipv6.ToString(), key.GetString(), rateLimited);
    }

    private static string? ReadProfileString(JsonElement data, string name) =>
        data.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    internal async Task Release(string token, CancellationToken cancel)
    {
        using var response = await PostWithRouteRecovery("release", token, new { }, cancel);
    }

    private async Task<JsonDocument> Post(string action, string? token, object value, CancellationToken cancel,
        AccountRoute? route = null, bool recordProtocol = true)
    {
        route ??= _active ?? throw new IOException("LOGIN_REQUIRED");
        // Give the WSGI account server a known body length on HTTP/1.1.
        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, action)
        {
            Content = content, Version = route.Version, VersionPolicy = route.Policy,
        };
        // HttpClient uses the Host header for both HTTP authority and TLS SNI
        // when the request URI uses an already resolved IP.
        if (route.AddressProof is not null) request.Headers.Host = Address.IdnHost;
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            using var response = await route.Http.SendAsync(request, cancel);
            Interlocked.Exchange(ref route.LastResponse, Stopwatch.GetTimestamp());
            if (recordProtocol) ResponseVersion = response.Version;
            var body = await response.Content.ReadAsByteArrayAsync(cancel);
            JsonDocument data;
            try
            {
                data = JsonDocument.Parse(body);
            }
            catch (JsonException)
            {
                throw new IOException(response.IsSuccessStatusCode ? "ACCOUNT_RESPONSE_INVALID" : "ACCOUNT_SERVICE_UNAVAILABLE");
            }
            if (data.RootElement.ValueKind != JsonValueKind.Object)
            {
                data.Dispose();
                throw new IOException("ACCOUNT_RESPONSE_INVALID");
            }
            if (response.IsSuccessStatusCode) return data;
            using (data)
            {
                if (data.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String &&
                    error.GetString() is { Length: > 0 and <= 80 } code &&
                    code.All(c => char.IsAsciiLetterUpper(c) || c == '_'))
                    throw new IOException(code);
            }
            throw new IOException("ACCOUNT_SERVICE_UNAVAILABLE");
        }
        catch (HttpRequestException error)
        {
            throw new IOException(error.HttpRequestError switch
            {
                HttpRequestError.NameResolutionError => "ACCOUNT_DNS_FAILED",
                HttpRequestError.ConnectionError => "ACCOUNT_CONNECT_FAILED",
                HttpRequestError.SecureConnectionError => "ACCOUNT_TLS_FAILED",
                HttpRequestError.ProxyTunnelError => "ACCOUNT_PROXY_FAILED",
                HttpRequestError.HttpProtocolError or HttpRequestError.VersionNegotiationError or
                    HttpRequestError.ResponseEnded or HttpRequestError.InvalidResponse => "ACCOUNT_HTTP_FAILED",
                _ => "ACCOUNT_SERVICE_UNAVAILABLE",
            }, error);
        }
        catch (OperationCanceledException error) when (!cancel.IsCancellationRequested)
        {
            throw new IOException("ACCOUNT_TIMEOUT", error);
        }
    }

    private static async Task DisposeWhenReady(Task<AccountRoute?> preparation)
    {
        try { (await preparation)?.Dispose(); }
        catch (Exception error) when (error is IOException or HttpRequestException or OperationCanceledException
            or NotSupportedException) { }
    }

    public void Dispose()
    {
        _active?.Dispose();
        if (_preparation is not null) _ = DisposeWhenReady(_preparation);
    }

}

internal sealed record ExitProfile(Uri Coordinator, long NodeId, string IPv4, string IPv6,
    string? Key, bool? RateLimited);
