using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.Tailscale;

internal sealed class LocalControl : IDisposable
{
    internal const string PipePrefix = @"ProtectedPrefix\Administrators\OracleProxyTailscale-";
    private readonly HttpClient _client;

    internal LocalControl(string instance)
    {
        if (!Regex.IsMatch(instance, "^[a-zA-Z0-9-]{1,40}\\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("INVALID_TAILSCALE_PIPE_INSTANCE", nameof(instance));

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            ConnectCallback = async (_, cancellation) =>
            {
                var pipe = new NamedPipeClientStream(".", PipePrefix + instance, PipeDirection.InOut,
                    PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
                try
                {
                    await pipe.ConnectAsync(cancellation);
                    return pipe;
                }
                catch
                {
                    pipe.Dispose();
                    throw;
                }
            },
        };
        _client = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://local-tailscaled.sock/"),
            Timeout = TimeSpan.FromSeconds(3),
            MaxResponseContentBufferSize = 65_536,
        };
    }

    internal async Task<DaemonState> ReadState(CancellationToken cancellation = default)
    {
        using var response = await _client.GetAsync("localapi/v0/status?peers=false", cancellation);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
        var root = body.RootElement;
        var state = root.GetProperty("BackendState").GetString()
            ?? throw new IOException("INVALID_TAILSCALE_BACKEND_STATE");
        bool hasNodeKey = root.TryGetProperty("HaveNodeKey", out var key) && key.GetBoolean();
        return new DaemonState(state, hasNodeKey);
    }

    public void Dispose() => _client.Dispose();
}

internal readonly record struct DaemonState(string State, bool HasNodeKey);
