using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal sealed class AccountApi : IDisposable
{
    internal static readonly Uri Base = new("https://vpn-admin.morandi.dpdns.org/");
    private readonly HttpClient _http;
    internal AccountApi()
    {
        var handler=new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(8),
            ConnectCallback=async (context,token)=>{
                if(context.DnsEndPoint.Host!=Base.Host || context.DnsEndPoint.Port!=443)throw new IOException("UNTRUSTED_API_ENDPOINT");
                var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
                try{await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse("152.67.156.100"),443),token);return new NetworkStream(socket,true);}
                catch{socket.Dispose();throw;}
            }};
        // TLS validation and SNI still use Base.Host. Only DNS is pinned to the
        // administrator's Oracle IPv4 so recovery never needs external DNS.
        _http=new HttpClient(handler){BaseAddress=Base,Timeout=TimeSpan.FromSeconds(12)};
    }
    internal async Task<JsonObject> Call(string action,string token,JsonObject? body=null)
    {
        if(action is not ("login" or "state" or "logout"))throw new InvalidOperationException();
        using var request=new HttpRequestMessage(body is null?HttpMethod.Get:HttpMethod.Post,"api/client/"+action);
        if(token.Length>0)request.Headers.Authorization=new("Bearer",token);
        if(body is not null)request.Content=new StringContent(body.ToJsonString(),Encoding.UTF8,"application/json");
        using var result=await _http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead);
        await using var stream=await result.Content.ReadAsStreamAsync();using var memory=new MemoryStream();var buffer=new byte[4096];
        int n;while((n=await stream.ReadAsync(buffer))!=0){if(memory.Length+n>32768)throw new IOException("API_RESPONSE_TOO_LARGE");memory.Write(buffer,0,n);}
        var value=JsonNode.Parse(memory.ToArray())?.AsObject() ?? throw new IOException("INVALID_API_RESPONSE");
        if(!result.IsSuccessStatusCode)throw new ApiException(value["error"]?.GetValue<string>() ?? "API_UNAVAILABLE");
        return value;
    }
    public void Dispose()=>_http.Dispose();
}
internal sealed class ApiException(string code):Exception(code);
