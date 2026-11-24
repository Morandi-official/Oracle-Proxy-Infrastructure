using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.Tailscale;

internal sealed class LocalControl : IDisposable
{
    internal const string PipePrefix = @"ProtectedPrefix\Administrators\OracleProxyTailscale-";
    private const string Api = "localapi/v0/";
    private static readonly Regex EnrollmentKey = new(@"\Ahskey-auth-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}\z",
        RegexOptions.CultureInvariant);
    private readonly HttpClient _client;
    private readonly CancellationTokenSource _watchLifetime = new();
    private HttpResponseMessage? _watch;
    private Task? _watchReader;

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
        if (_watchReader is { IsCompleted: true })
            throw new IOException("TAILSCALE_USER_PROFILE_WATCH_ENDED");
        using var response = await _client.GetAsync(Api + "status?peers=false", cancellation);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
        var root = body.RootElement;
        var state = root.GetProperty("BackendState").GetString()
            ?? throw new IOException("INVALID_TAILSCALE_BACKEND_STATE");
        bool hasNodeKey = root.TryGetProperty("HaveNodeKey", out var key) && key.GetBoolean();
        var exit = root.TryGetProperty("ExitNodeStatus", out var selected) && selected.ValueKind == JsonValueKind.Object
            && selected.TryGetProperty("ID", out var id) ? id.GetString() ?? "" : "";
        return new DaemonState(state, hasNodeKey, exit);
    }

    internal async Task KeepWindowsProfileSelected(CancellationToken cancellation)
    {
        // Windows clears the current actor when its last LocalAPI request
        // finishes. Keep a watcher open, as the upstream desktop client does,
        // so enrollment and routing stay attached to the Windows profile.
        // NotifyNoNetMap (8192) omits bulky configuration from notifications.
        var watch = await _client.GetAsync(Api + "watch-ipn-bus?mask=8192",
            HttpCompletionOption.ResponseHeadersRead, cancellation);
        try
        {
            // tailscaled binds the pipe before its backend is initialized.
            if (watch.StatusCode == HttpStatusCode.ServiceUnavailable)
                watch.EnsureSuccessStatusCode();
            if (!watch.IsSuccessStatusCode)
                throw new IOException("TAILSCALE_USER_PROFILE_WATCH_REJECTED");
            var stream = await watch.Content.ReadAsStreamAsync(cancellation);
            _watch = watch;
            _watchReader = DrainWatch(stream, _watchLifetime.Token);
        }
        catch
        {
            watch.Dispose();
            throw;
        }
    }

    private static async Task DrainWatch(Stream stream, CancellationToken cancellation)
    {
        try
        {
            byte[] buffer = new byte[4096];
            while (await stream.ReadAsync(buffer, cancellation).ConfigureAwait(false) != 0) { }
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // ReadState reports the closed subscription without daemon output.
        }
    }

    internal async Task Enroll(Uri coordinator, string credential, CancellationToken cancellation = default)
    {
        if (!coordinator.IsAbsoluteUri || coordinator.Scheme != Uri.UriSchemeHttps ||
            coordinator.HostNameType != UriHostNameType.Dns || !coordinator.IsDefaultPort ||
            coordinator.UserInfo.Length != 0 || coordinator.PathAndQuery != "/" || coordinator.Fragment.Length != 0)
            throw new ArgumentException("INVALID_TAILSCALE_COORDINATOR", nameof(coordinator));
        if (!EnrollmentKey.IsMatch(credential))
            throw new ArgumentException("INVALID_TAILSCALE_ENROLLMENT", nameof(credential));
        if ((await ReadState(cancellation)).HasNodeKey)
            throw new IOException("TAILSCALE_DEVICE_ALREADY_REGISTERED");

        await Send(HttpMethod.Post, "start", new
        {
            AuthKey = credential,
            UpdatePrefs = new
            {
                ControlURL = coordinator.GetLeftPart(UriPartial.Authority),
                WantRunning = true,
                ShieldsUp = true,
                CorpDNS = true,
                RouteAll = false,
            },
        }, cancellation);
        await Send(HttpMethod.Post, "login-interactive", null, cancellation);
    }

    internal Task SelectExitNode(long nodeId, CancellationToken cancellation = default)
    {
        if (nodeId <= 0)
            throw new ArgumentOutOfRangeException(nameof(nodeId));
        return Send(HttpMethod.Patch, "prefs", new
        {
            ExitNodeID = nodeId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ExitNodeIDSet = true,
            ExitNodeIPSet = true,
            ExitNodeAllowLANAccess = false,
            ExitNodeAllowLANAccessSet = true,
            WantRunning = true,
            WantRunningSet = true,
        }, cancellation);
    }

    internal Task Stop(CancellationToken cancellation = default) =>
        Send(HttpMethod.Patch, "prefs", new { WantRunning = false, WantRunningSet = true }, cancellation);

#if RETAINED_COORDINATOR_ACCEPTANCE
    internal Task ClearExitForProbe(CancellationToken cancellation) =>
        Send(HttpMethod.Patch, "prefs", new
        {
            ExitNodeID = "",
            ExitNodeIDSet = true,
            ExitNodeIPSet = true,
            WantRunning = true,
            WantRunningSet = true,
        }, cancellation);
#endif

    internal async Task<string> ReadExitTransport(long nodeId, CancellationToken cancellation)
    {
        using var response = await _client.GetAsync(Api + "status", cancellation);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
        if (body.RootElement.TryGetProperty("Peer", out var peers) && peers.ValueKind == JsonValueKind.Object)
        {
            string id = nodeId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            foreach (var candidate in peers.EnumerateObject())
            {
                var peer = candidate.Value;
                if (!peer.TryGetProperty("ID", out var value) || value.GetString() != id)
                    continue;
                if (peer.TryGetProperty("CurAddr", out var address) && !string.IsNullOrEmpty(address.GetString()))
                    return "direct";
                if (peer.TryGetProperty("PeerRelay", out var peerRelay) && !string.IsNullOrEmpty(peerRelay.GetString()))
                    return "peer-relay";
                if (peer.TryGetProperty("Relay", out var relay) && !string.IsNullOrEmpty(relay.GetString()))
                    return "derp";
            }
        }
        return "unknown";
    }

    private async Task Send(HttpMethod method, string action, object? value, CancellationToken cancellation)
    {
        using var request = new HttpRequestMessage(method, Api + action);
        if (value is not null)
        {
            var body = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
            body.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Content = body;
        }
        using var response = await _client.SendAsync(request, cancellation);
        if (!response.IsSuccessStatusCode)
            throw new IOException("TAILSCALE_LOCAL_CONTROL_REJECTED");
    }

    public void Dispose()
    {
        _watchLifetime.Cancel();
        _watch?.Dispose();
        _client.Dispose();
        _watchLifetime.Dispose();
    }
}

internal readonly record struct DaemonState(string State, bool HasNodeKey, string ExitId);
