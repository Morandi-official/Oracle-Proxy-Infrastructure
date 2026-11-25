using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OracleProxy.Tailscale;

internal sealed class AccountClient : IDisposable
{
    private static readonly Uri Address = new("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/");
    private readonly HttpClient _direct = CreateHttp(null);
    private HttpClient? _systemProxy;

    private static HttpClient CreateHttp(IWebProxy? proxy) => new(new SocketsHttpHandler
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

    internal async Task<string> Login(string username, string password, string device, CancellationToken cancel)
    {
        var payload = new { username, password, device };
        _systemProxy?.Dispose();
        _systemProxy = null;
        try
        {
            using var result = await Post("login", null, payload, cancel);
            return ReadToken(result);
        }
        catch (IOException error) when (error.Message is "ACCOUNT_DNS_FAILED" or "ACCOUNT_CONNECT_FAILED" or "ACCOUNT_TIMEOUT")
        {
            cancel.ThrowIfCancellationRequested();
            // Honor the existing Windows proxy settings for the same HTTPS account endpoint.
            // Authentication failures and TLS errors never enter this fallback.
            var proxy = HttpClient.DefaultProxy;
            bool bypass;
            try
            {
                bypass = await Task.Run(() => proxy.IsBypassed(Address), cancel)
                    .WaitAsync(TimeSpan.FromSeconds(3), cancel);
            }
            catch (TimeoutException proxyTimeout)
            {
                throw new IOException("ACCOUNT_PROXY_FAILED", proxyTimeout);
            }
            if (bypass) throw;
            var client = CreateHttp(proxy);
            try
            {
                using var result = await Post("login", null, payload, cancel, client);
                string token = ReadToken(result);
                _systemProxy = client;
                return token;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }
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
        HttpClient? client = null)
    {
        // Give the WSGI account server a known body length on HTTP/1.1.
        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, action) { Content = content };
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            using var response = await (client ?? _systemProxy ?? _direct).SendAsync(request, cancel);
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
        _systemProxy?.Dispose();
    }
}

internal sealed record ExitProfile(Uri Coordinator, long NodeId, string IPv4, string IPv6,
    string? Key, bool? RateLimited);
