using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace OracleProxy.Tailscale;

internal sealed class AccountClient : IDisposable
{
    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
    })
    {
        BaseAddress = new Uri("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/"),
        Timeout = TimeSpan.FromSeconds(12),
        MaxResponseContentBufferSize = 16_384,
    };

    internal async Task<string> Login(string username, string password, string device, CancellationToken cancel)
    {
        using var response = await Post("login", null, new { username, password, device }, cancel);
        return response.RootElement.GetProperty("token").GetString() ?? throw new IOException("LOGIN_REQUIRED");
    }

    internal async Task<ExitProfile> Profile(string token, bool confirm, CancellationToken cancel)
    {
        using var response = await Post(confirm ? "confirm" : "profile", token, new { }, cancel);
        var data = response.RootElement;
        return new ExitProfile(new Uri(data.GetProperty("coordinator").GetString()!),
            long.Parse(data.GetProperty("exit_node_id").GetString()!, CultureInfo.InvariantCulture),
            data.GetProperty("ipv4").GetString()!, data.GetProperty("ipv6").GetString()!,
            data.GetProperty("enrollment_key").GetString());
    }

    internal async Task Release(string token, CancellationToken cancel)
    {
        using var response = await Post("release", token, new { }, cancel);
    }

    private async Task<JsonDocument> Post(string action, string? token, object value, CancellationToken cancel)
    {
        // Give the WSGI account server a known body length on HTTP/1.1.
        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, action) { Content = content };
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _http.SendAsync(request, cancel);
        var body = await response.Content.ReadAsByteArrayAsync(cancel);
        if (response.IsSuccessStatusCode) return JsonDocument.Parse(body);
        try
        {
            using var error = JsonDocument.Parse(body);
            var code = error.RootElement.GetProperty("error").GetString();
            if (code is { Length: > 0 and <= 80 } && code.All(c => char.IsAsciiLetterUpper(c) || c == '_'))
                throw new IOException(code);
        }
        catch (JsonException) { }
        catch (KeyNotFoundException) { }
        throw new IOException("ACCOUNT_SERVICE_UNAVAILABLE");
    }

    public void Dispose() => _http.Dispose();
}

internal sealed record ExitProfile(Uri Coordinator, long NodeId, string IPv4, string IPv6, string? Key);
