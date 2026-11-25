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
    private long _preparationStarted;
    private AccountRoute? _active;

    internal Version? ResponseVersion { get; private set; }
    internal string? LoginRoute => _active?.Kind;

    private sealed class AccountRoute(string kind, IWebProxy? proxy, Version version, HttpVersionPolicy policy,
        IPAddress? address = null) : IDisposable
    {
        internal string Kind { get; } = kind;
        internal Version Version { get; } = version;
        internal HttpVersionPolicy Policy { get; } = policy;
        internal IPAddress? AddressProof { get; } = address;

        internal HttpClient Http { get; } = new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = proxy is not null,
            Proxy = proxy,
            ConnectTimeout = kind == "direct" ? TimeSpan.FromSeconds(5) : AlternateDeadline,
        })
        {
            BaseAddress = address is null ? Address : new UriBuilder(Address) { Host = address.ToString() }.Uri,
            Timeout = kind == "direct" ? TimeSpan.FromSeconds(12) : AlternateDeadline,
            MaxResponseContentBufferSize = 16_384,
        };

        public void Dispose() => Http.Dispose();
    }

    internal Task PrepareLogin(CancellationToken cancel)
    {
        if (_preparation is not null)
            return _preparation;

        _preparationStarted = Stopwatch.GetTimestamp();
        return _preparation = FindLoginRoute(cancel);
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

        var payload = new { username, password, device };
        try
        {
            cancel.ThrowIfCancellationRequested();
            try
            {
                using var result = await Post("login", null, payload, cancel, route);
                string token = ReadToken(result);
                _active = route;
                return token;
            }
            catch (IOException error) when (CanTryAnotherRoute(error))
            {
                // A stale connection or a network change can invalidate a warmed route.
                // Verify another route before repeating the stateless sign-in request.
                tryingAlternate?.Invoke();
                route.Dispose();
                route = await FindLoginRoute(cancel) ?? throw new IOException("ACCOUNT_ROUTE_TIMEOUT", error);
                using var result = await Post("login", null, payload, cancel, route);
                string token = ReadToken(result);
                _active = route;
                return token;
            }
        }
        finally
        {
            if (!ReferenceEquals(route, _active)) route.Dispose();
        }
    }

    private static bool CanTryAnotherRoute(IOException error) => error.Message is
        "ACCOUNT_DNS_FAILED" or "ACCOUNT_CONNECT_FAILED" or "ACCOUNT_TIMEOUT" or "ACCOUNT_HTTP_FAILED" or "ACCOUNT_PROXY_FAILED";

    internal IPAddress? CoordinatorAddressProof(Uri coordinator) =>
        coordinator.IsAbsoluteUri && coordinator.Scheme == Uri.UriSchemeHttps &&
        coordinator.Port == 443 && coordinator.IdnHost.Equals(Address.IdnHost, StringComparison.OrdinalIgnoreCase)
            ? _active?.AddressProof : null;

    private async Task<AccountRoute?> FindLoginRoute(CancellationToken cancel)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(AlternateDeadline);
        var ordinary = TryRoute(new("direct", null, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower),
            limit.Token);
        var pending = new List<Task<AccountRoute?>> { ordinary };
        AccountRoute? selected = null;
        try
        {
            await Task.WhenAny(ordinary, Task.Delay(150, limit.Token));
            if (ordinary.IsCompleted)
            {
                pending.Remove(ordinary);
                selected = await ordinary;
            }
            if (selected is null && !limit.IsCancellationRequested)
            {
                var addresses = TryResolveAccountAddress(limit.Token);
                pending.Add(TryEncryptedDns(addresses, http3: false, limit.Token));
                if (System.Net.Quic.QuicConnection.IsSupported)
                    pending.Add(TryEncryptedDns(addresses, http3: true, limit.Token));
                pending.Add(TryWindowsProxy(limit.Token));
                pending.Add(TryRoute(new("http1", null, HttpVersion.Version11, HttpVersionPolicy.RequestVersionExact),
                    limit.Token));
            }
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
            await limit.CancelAsync();
            foreach (var probe in pending)
                (await probe)?.Dispose();
        }
    }

    private async Task<AccountRoute?> TryWindowsProxy(CancellationToken cancel)
    {
        try
        {
            var proxy = HttpClient.DefaultProxy;
            var bypass = await Task.Run(() => proxy.IsBypassed(Address), cancel)
                .WaitAsync(TimeSpan.FromSeconds(3), cancel);
            return bypass ? null : await TryRoute(
                new("system-proxy", proxy, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower), cancel);
        }
        catch (Exception error) when (error is TimeoutException or OperationCanceledException or HttpRequestException or IOException)
        {
            return null;
        }
    }

    private async Task<AccountRoute?> TryRoute(AccountRoute route, CancellationToken cancel)
    {
        // This native API check has no secret and is rejected before the login rate limit.
        bool verified = false;
        try
        {
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

    private async Task<AccountRoute?> TryEncryptedDns(Task<List<IPAddress>> addresses, bool http3, CancellationToken cancel)
    {
        foreach (var ip in await addresses)
        {
            var route = http3
                ? new AccountRoute("encrypted-dns-http3", null, HttpVersion.Version30, HttpVersionPolicy.RequestVersionExact, ip)
                : new AccountRoute("encrypted-dns-tcp", null, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower, ip);
            if (await TryRoute(route, cancel) is { } verified) return verified;
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
        try { return await ResolveAccountAddress(cancel); }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or OperationCanceledException)
        {
            return [];
        }
    }

    private static async Task<List<IPAddress>> ResolveAccountAddress(CancellationToken cancel)
    {
        // Only the fixed account hostname is sent to an authenticated resolver.
        using var query = new HttpRequestMessage(HttpMethod.Get,
            "https://1.1.1.1/dns-query?type=A&name=" + Uri.EscapeDataString(Address.IdnHost));
        query.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));
        using var reply = await EncryptedDns.SendAsync(query, cancel);
        reply.EnsureSuccessStatusCode();
        using var result = JsonDocument.Parse(await reply.Content.ReadAsByteArrayAsync(cancel));
        if (!result.RootElement.TryGetProperty("Status", out var status) || !status.TryGetInt32(out int code) || code != 0 ||
            !result.RootElement.TryGetProperty("Answer", out var answers) || answers.ValueKind != JsonValueKind.Array)
            throw new IOException("ACCOUNT_ENCRYPTED_DNS_FAILED");

        var addresses = new List<IPAddress>();
        foreach (var answer in answers.EnumerateArray().Take(8))
        {
            if (answer.TryGetProperty("type", out var type) && type.TryGetInt32(out int kind) && kind == 1 &&
                answer.TryGetProperty("data", out var value) && value.ValueKind == JsonValueKind.String &&
                IPAddress.TryParse(value.GetString(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                IsPublicAddress(ip))
                addresses.Add(ip);
        }
        return addresses;
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

    internal async Task<ExitProfile> Profile(string token, bool confirm, CancellationToken cancel)
    {
        using var response = await Post(confirm ? "confirm" : "profile", token, new { }, cancel);
        var data = response.RootElement;
        bool? rateLimited = data.TryGetProperty("rate_limited", out var limited)
            && limited.ValueKind is JsonValueKind.True or JsonValueKind.False ? limited.GetBoolean() : null;
        return new ExitProfile(new Uri(data.GetProperty("coordinator").GetString()!),
            long.Parse(data.GetProperty("exit_node_id").GetString()!, CultureInfo.InvariantCulture),
            data.GetProperty("ipv4").GetString()!, data.GetProperty("ipv6").GetString()!,
            data.GetProperty("enrollment_key").GetString(), rateLimited);
    }

    internal async Task Release(string token, CancellationToken cancel)
    {
        using var response = await Post("release", token, new { }, cancel);
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
        catch (Exception error) when (error is IOException or HttpRequestException or OperationCanceledException) { }
    }

    public void Dispose()
    {
        _active?.Dispose();
        if (_preparation is not null) _ = DisposeWhenReady(_preparation);
    }

}

internal sealed record ExitProfile(Uri Coordinator, long NodeId, string IPv4, string IPv6,
    string? Key, bool? RateLimited);
