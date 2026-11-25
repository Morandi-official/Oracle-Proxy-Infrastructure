using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OracleProxy.Tailscale;

internal sealed class AccountClient : IDisposable
{
    private static readonly Uri Address = new("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/");
    private readonly AccountRoute _direct = new(null, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower);
    private AccountRoute? _alternate;

    internal Version? ResponseVersion { get; private set; }

    private sealed class AccountRoute(IWebProxy? proxy, Version version, HttpVersionPolicy policy) : IDisposable
    {
        internal Version Version { get; } = version;
        internal HttpVersionPolicy Policy { get; } = policy;

        internal HttpClient Http { get; } = new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = proxy is not null,
            Proxy = proxy,
            ConnectTimeout = TimeSpan.FromSeconds(5),
        })
        {
            BaseAddress = Address,
            Timeout = TimeSpan.FromSeconds(12),
            MaxResponseContentBufferSize = 16_384,
        };

        public void Dispose() => Http.Dispose();
    }

    internal async Task<string> Login(string username, string password, string device, CancellationToken cancel)
    {
        var payload = new { username, password, device };
        _alternate?.Dispose();
        _alternate = null;
        try
        {
            using var result = await Post("login", null, payload, cancel);
            return ReadToken(result);
        }
        catch (IOException error) when (CanTryAnotherRoute(error))
        {
            var route = await FindAlternate(cancel);
            if (route is null) throw;
            try
            {
                using var result = await Post("login", null, payload, cancel, route);
                string token = ReadToken(result);
                _alternate = route;
                return token;
            }
            finally
            {
                if (_alternate != route) route.Dispose();
            }
        }
    }

    private static bool CanTryAnotherRoute(IOException error) => error.Message is
        "ACCOUNT_DNS_FAILED" or "ACCOUNT_CONNECT_FAILED" or "ACCOUNT_TIMEOUT" or "ACCOUNT_HTTP_FAILED";

    private async Task<AccountRoute?> FindAlternate(CancellationToken cancel)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(7));
        var pending = new List<Task<AccountRoute?>>
        {
            TryRoute(new(null, HttpVersion.Version11, HttpVersionPolicy.RequestVersionExact), limit.Token),
            TryWindowsProxy(limit.Token),
        };
        if (System.Net.Quic.QuicConnection.IsSupported)
            pending.Add(TryRoute(new(null, HttpVersion.Version30, HttpVersionPolicy.RequestVersionExact), limit.Token));
        AccountRoute? selected = null;
        try
        {
            while (pending.Count > 0 && selected is null)
            {
                var next = await Task.WhenAny(pending);
                pending.Remove(next);
                selected = await next;
            }
            cancel.ThrowIfCancellationRequested();
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
                new(proxy, HttpVersion.Version20, HttpVersionPolicy.RequestVersionOrLower), cancel);
        }
        catch (Exception error) when (error is TimeoutException or OperationCanceledException or HttpRequestException)
        {
            return null;
        }
    }

    private async Task<AccountRoute?> TryRoute(AccountRoute route, CancellationToken cancel)
    {
        // Check the POST endpoint, without credentials or a bearer token. An
        // empty object is rejected before the server counts login attempts.
        bool verified = false;
        try
        {
            using var response = await Post("login", null, new { }, cancel, route, recordProtocol: false);
            return null;
        }
        catch (IOException error) when (error.Message == "INVALID_REQUEST")
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

    internal async Task<bool> VerifyHttp3LoginRoute(CancellationToken cancel)
    {
        if (!System.Net.Quic.QuicConnection.IsSupported) return false;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(5));
        using var verified = await TryRoute(new(null, HttpVersion.Version30, HttpVersionPolicy.RequestVersionExact), limit.Token);
        return verified is not null;
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
        route ??= _alternate ?? _direct;
        // Give the WSGI account server a known body length on HTTP/1.1.
        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, action)
        {
            Content = content, Version = route.Version, VersionPolicy = route.Policy,
        };
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

    public void Dispose()
    {
        _direct.Dispose();
        _alternate?.Dispose();
    }
}

internal sealed record ExitProfile(Uri Coordinator, long NodeId, string IPv4, string IPv6,
    string? Key, bool? RateLimited);
