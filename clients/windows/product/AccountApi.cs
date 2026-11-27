using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal sealed class AccountApi : IDisposable
{
    internal static readonly Uri Base = new("https://vpn-admin.morandi.dpdns.org/");
    private readonly HttpClient[] _disconnectedClients;
    private readonly HttpClient _physicalHttp;
    private readonly CancellationTokenSource _stop=new();
    private readonly object _routeGate=new();
    private Task<HttpClient>? _disconnectedRoute;
    private long _routeExpires;
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
        // Only the interface-bound pool is usable when protection is present.
        // A pinned address locates a socket; TLS still authenticates Base.Host.
        _physicalHttp=CreateClient((_,cancel)=>ConnectKnownRoute(bound:true,cancel));
        var system=CreateClient(ConnectSystemRoute,requireDisconnected:true);
        var pinned=CreateClient((_,cancel)=>ConnectKnownRoute(bound:false,cancel),requireDisconnected:true);
        _disconnectedClients=[system,_physicalHttp,pinned];
    }

#if ORACLE_PRODUCT_TESTS
    internal static async Task VerifyPublicPinnedRoute(CancellationToken cancel)
    {
        using var client=CreateClient((_,token)=>ConnectKnownRoute(bound:false,token));
        await VerifyAccountRoute(client,cancel).ConfigureAwait(false);
    }
#endif

    private static HttpClient CreateClient(Func<DnsEndPoint,CancellationToken,Task<Stream>> connect,bool requireDisconnected=false)
    {
        var handler = new SocketsHttpHandler {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(24),
            PooledConnectionIdleTimeout=TimeSpan.FromSeconds(20),
        };
        handler.ConnectCallback = async (context, token) => {
            if (context.DnsEndPoint.Host != Base.Host || context.DnsEndPoint.Port != 443)
                throw new IOException("UNTRUSTED_API_ENDPOINT");
            if(requireDisconnected && !NativeGuard.ConfirmedAbsent)throw new IOException("ACCOUNT_SYSTEM_ROUTE_PROTECTED");
            return await connect(context.DnsEndPoint,token).ConfigureAwait(false);
        };
        return new HttpClient(handler){BaseAddress=Base,Timeout=Timeout.InfiniteTimeSpan};
    }

    internal void WarmDisconnectedRoute()
    {
        var route=GetDisconnectedRoute();
        _=route.ContinueWith(t=>{_ = t.Exception;},CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }

    private Task<HttpClient> GetDisconnectedRoute()
    {
        lock(_routeGate){
            if(_disconnectedRoute is null || _disconnectedRoute.IsFaulted || _disconnectedRoute.IsCanceled ||
                Environment.TickCount64>=_routeExpires){
                _routeExpires=Environment.TickCount64+45_000;
                _disconnectedRoute=Task.Run(FindDisconnectedRoute);
            }
            return _disconnectedRoute;
        }
    }

    private Task<HttpClient> FindDisconnectedRoute()=>SelectVerifiedRoute(_disconnectedClients,(client,cancel)=>
        NativeGuard.ConfirmedAbsent?VerifyAccountRoute(client,cancel):Task.FromException(new IOException("ACCOUNT_SYSTEM_ROUTE_PROTECTED")),_stop.Token);

    private static HttpRequestMessage Request(HttpMethod method,string action)
    {
        var request=new HttpRequestMessage(method,"api/client/"+action);
        request.Headers.Add("X-Oracle-Client-Capabilities","dual-stack-v1");
        if(action=="authenticate")request.Headers.Add("X-Oracle-Confirm-Device","true");
        return request;
    }

    internal static async Task VerifyAccountRoute(HttpClient client,CancellationToken cancel)
    {
        // Exercise the exact POST path without a username, device key or token.
        // The server rejects missing fields before throttling or mutating state.
        using var request=Request(HttpMethod.Post,"authenticate");
        request.Content=new StringContent("{}",Encoding.UTF8,"application/json");
        using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancel).ConfigureAwait(false);
        if(response.StatusCode!=HttpStatusCode.BadRequest)throw new HttpRequestException(
            "ACCOUNT_ROUTE_PROBE_REJECTED",null,response.StatusCode);
        await response.Content.LoadIntoBufferAsync(1024,cancel).ConfigureAwait(false);
        var value=JsonNode.Parse(await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false));
        if(value is not JsonObject state || state["error"] is not JsonValue error ||
            !error.TryGetValue<string>(out var code) || code!="INVALID_REQUEST")throw new IOException("ACCOUNT_ROUTE_PROBE_REJECTED");
    }

    internal static async Task<HttpClient> SelectVerifiedRoute(IReadOnlyList<HttpClient> clients,
        Func<HttpClient,CancellationToken,Task> verify,CancellationToken cancel)
    {
        using var race=CancellationTokenSource.CreateLinkedTokenSource(cancel);
        race.CancelAfter(TimeSpan.FromSeconds(26));
        async Task<(HttpClient Route,Exception? Failure)> Probe(HttpClient route)
        {
            try{
                await verify(route,race.Token).ConfigureAwait(false);
                return (route,null);
            }
            catch(Exception error)when(error is HttpRequestException or IOException or OperationCanceledException or System.Text.Json.JsonException or ObjectDisposedException or NotSupportedException){
                return (route,error);
            }
        }
        try{
            var preferred=Probe(clients[0]);
            if(await Task.WhenAny(preferred,Task.Delay(200,race.Token)).ConfigureAwait(false)==preferred &&
                (await preferred.ConfigureAwait(false)).Failure is null){
                race.Token.ThrowIfCancellationRequested();return clients[0];
            }
            var pending=new List<Task<(HttpClient Route,Exception? Failure)>>{preferred};
            pending.AddRange(clients.Skip(1).Select(Probe));
            Exception? failure=null;
            while(pending.Count>0){
                var finished=await Task.WhenAny(pending).WaitAsync(race.Token).ConfigureAwait(false);
                pending.Remove(finished);
                var result=await finished.ConfigureAwait(false);
                if(result.Failure is null){race.Token.ThrowIfCancellationRequested();return result.Route;}
                if(failure is null or OperationCanceledException || result.Route==clients[0])failure=result.Failure;
            }
            throw new AccountTransportException("ROUTE_PROBE",failure);
        }catch(OperationCanceledException error)when(!cancel.IsCancellationRequested){
            throw new AccountTransportException("ROUTE_PROBE",error);
        }finally{
            race.Cancel();
        }
    }

    private static async Task<Stream> ConnectSystemRoute(DnsEndPoint endpoint,CancellationToken cancel)
    {
        var socket=new Socket(SocketType.Stream,ProtocolType.Tcp);
        try{
            socket.NoDelay=true;
            await socket.ConnectAsync(endpoint,cancel).ConfigureAwait(false);
            return new NetworkStream(socket,ownsSocket:true);
        }catch{socket.Dispose();throw;}
    }

    private static async Task<Stream> ConnectKnownRoute(bool bound,CancellationToken cancel)
    {
        uint? physical=bound?NativeGuard.PhysicalIPv4Index:null;
        if(physical==0)throw new IOException("PHYSICAL_ROUTE_UNAVAILABLE");
        var tried = new HashSet<string>();
        Exception? failure=null;
        async Task<Stream?> TryAddress(string address)
        {
            if (!tried.Add(address)) return null;
            var endpoint = new IPEndPoint(IPAddress.Parse(EndpointCatalog.Public(address)), 443);
            var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
            try{
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancel);
                timeout.CancelAfter(bound?1_500:18_000);socket.NoDelay=true;
                if(physical is uint index)
                    socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)index));
                await socket.ConnectAsync(endpoint,timeout.Token).ConfigureAwait(false);
                return new NetworkStream(socket,ownsSocket:true);
            }catch(Exception error)when(error is SocketException or OperationCanceledException or IOException){
                socket.Dispose();cancel.ThrowIfCancellationRequested();failure=error;return null;
            }
        }

        string[] known;
        lock (AddressGate) { known = KnownAddresses; }
        foreach (string address in ConnectionCandidates(known)) {
            var stream = await TryAddress(address).ConfigureAwait(false);
            if (stream is not null) return stream;
        }
        if(physical is uint selected){
            foreach(string address in await PhysicalDns.Resolve(selected,cancel).ConfigureAwait(false)){
                var stream=await TryAddress(address).ConfigureAwait(false);
                if(stream is not null)return stream;
            }
        }
        throw new IOException("API_ENDPOINTS_UNAVAILABLE",failure);
    }

    internal Task<JsonObject> Call(string action,string token,JsonObject? body=null)=>Call(action,token,body,CancellationToken.None);
    internal async Task<JsonObject> Call(string action,string token,JsonObject? body,CancellationToken cancel)
    {
        if(action is not ("login" or "authenticate" or "enroll" or "presence" or "state" or "logout" or "udp-diagnostics" or "device-delete"))throw new InvalidOperationException();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token,cancel);
        // Password login is interactive and can await a slow first HTTPS
        // connection. Presence and connected policy reads keep their limit.
        deadline.CancelAfter(TimeSpan.FromSeconds(action=="authenticate"?42:12));
        using var result=await Send(action,token,body,deadline.Token);
        using var memory=new MemoryStream();var buffer=new byte[4096];
        try{
            await using var stream=await result.Content.ReadAsStreamAsync(deadline.Token);
            int n;while((n=await stream.ReadAsync(buffer,deadline.Token))!=0){if(memory.Length+n>65536)throw new IOException("API_RESPONSE_TOO_LARGE");memory.Write(buffer,0,n);}
        }catch(Exception error)when(error is HttpRequestException or HttpIOException || error is OperationCanceledException && !_stop.IsCancellationRequested){
            throw new AccountTransportException("RESPONSE",error);
        }
        var value=JsonNode.Parse(memory.ToArray())?.AsObject() ?? throw new IOException("INVALID_API_RESPONSE");
        if(!result.IsSuccessStatusCode)throw new ApiException(value["error"]?.GetValue<string>() ?? "API_UNAVAILABLE");
        EndpointCatalog.Normalize(value);Remember(value);return value;
    }
    private async Task<HttpResponseMessage> Send(string action,string token,JsonObject? body,CancellationToken cancel)
    {
        Task<HttpClient>? route=null;
        string phase="ROUTE_PROBE";
        try{
            var client=_physicalHttp;
            if(NativeGuard.ConfirmedAbsent){
                route=GetDisconnectedRoute();
                try{
                    var verified=await route.WaitAsync(cancel);
                    if(NativeGuard.ConfirmedAbsent)client=verified;
                }catch(IOException)when(!NativeGuard.ConfirmedAbsent){
                    // Protection may have changed while the anonymous probe ran.
                    // No authenticated request has been sent.
                }
            }
            phase="REQUEST";
            using var request=Request(body is null?HttpMethod.Get:HttpMethod.Post,action);
            if(token.Length>0)request.Headers.Authorization=new("Bearer",token);
            if(body is not null)request.Content=new StringContent(body.ToJsonString(),Encoding.UTF8,"application/json");
            return await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancel);
        }
        catch(Exception error)when(error is HttpRequestException || error is OperationCanceledException && !_stop.IsCancellationRequested){
            lock(_routeGate){if(ReferenceEquals(_disconnectedRoute,route))_disconnectedRoute=null;}
            throw new AccountTransportException(phase,error);
        }
    }
    internal void Cancel()=>_stop.Cancel();
    public void Dispose(){_stop.Cancel();foreach(var client in _disconnectedClients)client.Dispose();_stop.Dispose();}
}
internal sealed class AccountTransportException(string phase,Exception? error):IOException("ACCOUNT_API_UNREACHABLE",error)
{
    internal string Phase{get;}=phase;
}
internal sealed class ApiException(string code):Exception(code);
