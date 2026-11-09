using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal sealed class AccountApi : IDisposable
{
    internal static readonly Uri Base = new("https://vpn-admin.morandi.dpdns.org/");
    private readonly HttpClient _http;
    private readonly CancellationTokenSource _stop=new();
    private static readonly object AddressGate=new();
    private static string[] KnownAddresses=["152.67.154.225","150.230.113.158"];
    private static readonly string AddressCache=Path.Combine(Platform.StateRoot,"api-addresses.json");
    private static void Remember(JsonObject state)
    {
        var addresses=EndpointCatalog.Addresses(state);if(addresses.Length==0)return;
        lock(AddressGate){KnownAddresses=addresses;}
        try{if(Platform.IsSystem){Platform.VerifyProtected(Platform.StateRoot);if(File.Exists(AddressCache) && File.GetAttributes(AddressCache).HasFlag(FileAttributes.ReparsePoint))return;string temporary=AddressCache+".new";File.WriteAllText(temporary,new JsonArray(addresses.Select(a=>(JsonNode?)JsonValue.Create(a)).ToArray()).ToJsonString());File.Move(temporary,AddressCache,true);}}catch(IOException){}catch(UnauthorizedAccessException){}
    }
    internal AccountApi()
    {
        var handler=new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(8),
            ConnectCallback=async (context,token)=>{
                if(context.DnsEndPoint.Host!=Base.Host || context.DnsEndPoint.Port!=443)throw new IOException("UNTRUSTED_API_ENDPOINT");
                uint physical=NativeGuard.PhysicalIPv4Index;if(physical==0)throw new IOException("PHYSICAL_ROUTE_UNAVAILABLE");
                var tried=new HashSet<string>();
                async Task<Stream?> Try(string address){
                    if(!tried.Add(address))return null;
                    var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                    try{using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromMilliseconds(1500));socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)physical));await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(EndpointCatalog.Public(address)),443),timeout.Token);return new NetworkStream(socket,true);}
                    catch(Exception e) when(e is SocketException or OperationCanceledException or IOException){socket.Dispose();token.ThrowIfCancellationRequested();return null;}
                }
                string[] known;lock(AddressGate){known=KnownAddresses;}
                foreach(string address in known){var stream=await Try(address);if(stream is not null)return stream;}
                foreach(string address in await PhysicalDns.Resolve(physical,token)){var stream=await Try(address);if(stream is not null)return stream;}
                throw new IOException("API_ENDPOINTS_UNAVAILABLE");
            }};
        try{if(File.Exists(AddressCache) && !File.GetAttributes(AddressCache).HasFlag(FileAttributes.ReparsePoint) && new FileInfo(AddressCache).Length<=2048){if(JsonNode.Parse(File.ReadAllText(AddressCache)) is JsonArray cached && cached.Count is >0 and <=2 && cached.All(x=>x is JsonValue)){var addresses=cached.Select(x=>EndpointCatalog.Public(x!.GetValue<string>())).Distinct().ToArray();lock(AddressGate){KnownAddresses=addresses;}}}}catch(Exception e) when(e is IOException or System.Text.Json.JsonException or InvalidOperationException){}
        // TLS validation and SNI always use Base.Host. Authenticated catalog addresses
        // are tried first; physical-interface DNS provides future migration recovery.
        _http=new HttpClient(handler){BaseAddress=Base,Timeout=TimeSpan.FromSeconds(12)};
    }
    internal async Task<JsonObject> Call(string action,string token,JsonObject? body=null)
    {
        if(action is not ("login" or "authenticate" or "enroll" or "presence" or "state" or "logout" or "udp-diagnostics" or "device-delete"))throw new InvalidOperationException();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);deadline.CancelAfter(TimeSpan.FromSeconds(12));
        using var request=new HttpRequestMessage(body is null?HttpMethod.Get:HttpMethod.Post,"api/client/"+action);
        request.Headers.Add("X-Oracle-Client-Capabilities","dual-stack-v1");
        if(token.Length>0)request.Headers.Authorization=new("Bearer",token);
        if(body is not null)request.Content=new StringContent(body.ToJsonString(),Encoding.UTF8,"application/json");
        using var result=await _http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
        await using var stream=await result.Content.ReadAsStreamAsync(deadline.Token);using var memory=new MemoryStream();var buffer=new byte[4096];
        int n;while((n=await stream.ReadAsync(buffer,deadline.Token))!=0){if(memory.Length+n>65536)throw new IOException("API_RESPONSE_TOO_LARGE");memory.Write(buffer,0,n);}
        var value=JsonNode.Parse(memory.ToArray())?.AsObject() ?? throw new IOException("INVALID_API_RESPONSE");
        if(!result.IsSuccessStatusCode)throw new ApiException(value["error"]?.GetValue<string>() ?? "API_UNAVAILABLE");
        EndpointCatalog.Normalize(value);Remember(value);return value;
    }
    internal void Cancel()=>_stop.Cancel();
    public void Dispose(){_stop.Cancel();_http.Dispose();_stop.Dispose();}
}
internal sealed class ApiException(string code):Exception(code);
