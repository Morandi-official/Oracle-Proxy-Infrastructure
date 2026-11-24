using System.IO.Pipes;
using System.Net.Http.Json;
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
        using var response = await _client.GetAsync(Api + "status?peers=false", cancellation);
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
        var root = body.RootElement;
        var state = root.GetProperty("BackendState").GetString()
            ?? throw new IOException("INVALID_TAILSCALE_BACKEND_STATE");
        bool hasNodeKey = root.TryGetProperty("HaveNodeKey", out var key) && key.GetBoolean();
        return new DaemonState(state, hasNodeKey);
    }

    internal Task Enroll(Uri coordinator, string credential, CancellationToken cancellation = default)
    {
        if (!coordinator.IsAbsoluteUri || coordinator.Scheme != Uri.UriSchemeHttps ||
            coordinator.HostNameType != UriHostNameType.Dns || !coordinator.IsDefaultPort ||
            coordinator.UserInfo.Length != 0 || coordinator.PathAndQuery != "/" || coordinator.Fragment.Length != 0)
            throw new ArgumentException("INVALID_TAILSCALE_COORDINATOR", nameof(coordinator));
        if (!EnrollmentKey.IsMatch(credential))
            throw new ArgumentException("INVALID_TAILSCALE_ENROLLMENT", nameof(credential));

        return Send(HttpMethod.Post, "start", new
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

    private async Task Send(HttpMethod method, string action, object value, CancellationToken cancellation)
    {
        using var request = new HttpRequestMessage(method, Api + action) { Content = JsonContent.Create(value) };
        using var response = await _client.SendAsync(request, cancellation);
        if (!response.IsSuccessStatusCode)
            throw new IOException("TAILSCALE_LOCAL_CONTROL_REJECTED");
    }

    public void Dispose() => _client.Dispose();
}

internal readonly record struct DaemonState(string State, bool HasNodeKey);
