using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal sealed class AccountApi : IDisposable
{
    internal static readonly Uri Base = new("https://vpn-admin.morandi.dpdns.org/");
    private readonly HttpClient _directHttp;
    private readonly HttpClient _protectedHttp;
    private readonly CancellationTokenSource _stop=new();
    private static readonly object AddressGate=new();
    internal const string BootstrapAddress="152.67.156.100";
    private static string[] KnownAddresses=[];
    internal static string[] ConnectionCandidates(IEnumerable<string> known)=>
        known.Prepend(BootstrapAddress).Distinct(StringComparer.Ordinal).ToArray();
    private static readonly string AddressCache=Path.Combine(Platform.StateRoot,"api-addresses.json");
    private static void Remember(JsonObject state)
    {
        var addresses=EndpointCatalog.Addresses(state);
        if(addresses.Length==0 && state["tunnel"]?["transport_address"] is JsonValue value && value.TryGetValue<string>(out var address))
            addresses=[EndpointCatalog.Public(address)];
        if(addresses.Length==0)return;
        lock(AddressGate){KnownAddresses=addresses;}
        try{if(Platform.IsSystem){Platform.VerifyProtected(Platform.StateRoot);if(File.Exists(AddressCache) && File.GetAttributes(AddressCache).HasFlag(FileAttributes.ReparsePoint))return;string temporary=AddressCache+".new";File.WriteAllText(temporary,new JsonArray(addresses.Select(a=>(JsonNode?)JsonValue.Create(a)).ToArray()).ToJsonString());File.Move(temporary,AddressCache,true);}}catch(IOException){}catch(UnauthorizedAccessException){}
    }
    internal AccountApi()
    {
        try{if(File.Exists(AddressCache) && !File.GetAttributes(AddressCache).HasFlag(FileAttributes.ReparsePoint) && new FileInfo(AddressCache).Length<=2048){if(JsonNode.Parse(File.ReadAllText(AddressCache)) is JsonArray cached && cached.Count is >0 and <=2 && cached.All(x=>x is JsonValue)){var addresses=cached.Select(x=>EndpointCatalog.Public(x!.GetValue<string>())).Distinct().ToArray();lock(AddressGate){KnownAddresses=addresses;}}}}catch(Exception e) when(e is IOException or System.Text.Json.JsonException or InvalidOperationException){}
        // Separate pools keep a connection opened on the system route from
        // being reused after protection starts. Both validate the same TLS host.
        _directHttp = CreateClient(protectedPath: false);
        _protectedHttp = CreateClient(protectedPath: true);
    }

    private static HttpClient CreateClient(bool protectedPath)
    {
        var handler = new SocketsHttpHandler {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            ConnectCallback = (context, token) => ConnectAccount(
                context.DnsEndPoint, protectedPath || !NativeGuard.ConfirmedAbsent,
                TrySystemRoute, ConnectPhysicalRoute, token),
        };
        return new HttpClient(handler) { BaseAddress = Base, Timeout = TimeSpan.FromSeconds(12) };
    }

    internal static async ValueTask<Stream> ConnectAccount(
        DnsEndPoint endpoint,
        bool protectedPath,
        Func<DnsEndPoint, CancellationToken, Task<Stream?>> trySystemRoute,
        Func<CancellationToken, Task<Stream>> connectPhysicalRoute,
        CancellationToken cancel)
    {
        if (endpoint.Host != Base.Host || endpoint.Port != 443)
            throw new IOException("UNTRUSTED_API_ENDPOINT");
        cancel.ThrowIfCancellationRequested();
        if (!protectedPath) {
            var connection = await trySystemRoute(endpoint, cancel);
            if (connection is not null) return connection;
            cancel.ThrowIfCancellationRequested();
        }
        return await connectPhysicalRoute(cancel);
    }

    private static Task<Stream?> TrySystemRoute(DnsEndPoint endpoint, CancellationToken cancel) =>
        TrySocket(new Socket(SocketType.Stream, ProtocolType.Tcp), endpoint, null, 4_000, cancel);

    private static async Task<Stream> ConnectPhysicalRoute(CancellationToken cancel)
    {
        uint physical = NativeGuard.PhysicalIPv4Index;
        if (physical == 0) throw new IOException("PHYSICAL_ROUTE_UNAVAILABLE");
        var tried = new HashSet<string>();
        async Task<Stream?> TryAddress(string address)
        {
            if (!tried.Add(address)) return null;
            var endpoint = new IPEndPoint(IPAddress.Parse(EndpointCatalog.Public(address)), 443);
            return await TrySocket(
                new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp),
                endpoint, physical, 1_500, cancel);
        }

        string[] known;
        lock (AddressGate) { known = KnownAddresses; }
        foreach (string address in ConnectionCandidates(known)) {
            var stream = await TryAddress(address);
            if (stream is not null) return stream;
        }
        foreach (string address in await PhysicalDns.Resolve(physical, cancel)) {
            var stream = await TryAddress(address);
            if (stream is not null) return stream;
        }
        throw new IOException("API_ENDPOINTS_UNAVAILABLE");
    }

    private static async Task<Stream?> TrySocket(
        Socket socket, EndPoint endpoint, uint? physical, int timeoutMs, CancellationToken cancel)
    {
        try {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            timeout.CancelAfter(timeoutMs);
            socket.NoDelay = true;
            if (physical is uint index)
                socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder((int)index));
            await socket.ConnectAsync(endpoint, timeout.Token);
            return new NetworkStream(socket, ownsSocket: true);
        } catch (Exception error) when (error is SocketException or OperationCanceledException or IOException) {
            socket.Dispose();
            cancel.ThrowIfCancellationRequested();
            return null;
        }
    }

    internal async Task<JsonObject> Call(string action,string token,JsonObject? body=null)
    {
        if(action is not ("login" or "authenticate" or "enroll" or "presence" or "state" or "logout" or "udp-diagnostics" or "device-delete"))throw new InvalidOperationException();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);deadline.CancelAfter(TimeSpan.FromSeconds(12));
        using var request=new HttpRequestMessage(body is null?HttpMethod.Get:HttpMethod.Post,"api/client/"+action);
        request.Headers.Add("X-Oracle-Client-Capabilities","dual-stack-v1");
        if(token.Length>0)request.Headers.Authorization=new("Bearer",token);
        if(body is not null)request.Content=new StringContent(body.ToJsonString(),Encoding.UTF8,"application/json");
        using var result=await Send(request,deadline.Token);
        await using var stream=await result.Content.ReadAsStreamAsync(deadline.Token);using var memory=new MemoryStream();var buffer=new byte[4096];
        int n;while((n=await stream.ReadAsync(buffer,deadline.Token))!=0){if(memory.Length+n>65536)throw new IOException("API_RESPONSE_TOO_LARGE");memory.Write(buffer,0,n);}
        var value=JsonNode.Parse(memory.ToArray())?.AsObject() ?? throw new IOException("INVALID_API_RESPONSE");
        if(!result.IsSuccessStatusCode)throw new ApiException(value["error"]?.GetValue<string>() ?? "API_UNAVAILABLE");
        EndpointCatalog.Normalize(value);Remember(value);return value;
    }
    private async Task<HttpResponseMessage> Send(HttpRequestMessage request,CancellationToken cancel)
    {
        try{
            var client = NativeGuard.ConfirmedAbsent ? _directHttp : _protectedHttp;
            return await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancel);
        }
        catch(HttpRequestException error){throw new IOException("ACCOUNT_API_UNREACHABLE",error);}
        catch(OperationCanceledException error)when(!_stop.IsCancellationRequested){throw new IOException("ACCOUNT_API_UNREACHABLE",error);}
    }
    internal void Cancel()=>_stop.Cancel();
    public void Dispose(){_stop.Cancel();_directHttp.Dispose();_protectedHttp.Dispose();_stop.Dispose();}
}
internal sealed class ApiException(string code):Exception(code);
