using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Non-shipped timing fixture for the same direct and WireGuard IPv4 HTTPS path.
internal static class OraclePerformance
{
    private static readonly Uri Target=new("https://www.cloudflare.com/cdn-cgi/trace");
    private const int Samples=20,TraceLimit=8192,TargetMs=500;

    internal static async Task<IPAddress?> ResolveTarget()
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try{return (await Dns.GetHostAddressesAsync(Target.Host,AddressFamily.InterNetwork,deadline.Token)).FirstOrDefault();}
        catch(Exception error)when(error is SocketException or OperationCanceledException){return null;}
    }

    internal static async Task MeasureHttps(IPAddress? target,IReadOnlySet<string> allowedExits,bool tunneled)
    {
        await MeasureSeries(target,allowedExits,tunneled,reuse:false);
        await MeasureSeries(target,allowedExits,tunneled,reuse:true);
    }

    private static async Task MeasureSeries(IPAddress? target,IReadOnlySet<string> allowedExits,bool tunneled,bool reuse)
    {
        var samples=new List<long>(Samples);
        int attempts=0,connections=0;
        string route=tunneled?"wireguard":"direct";
        if(target is not null){
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var handler=new SocketsHttpHandler{
                UseProxy=false,UseCookies=false,AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(4),
                PooledConnectionLifetime=reuse?Timeout.InfiniteTimeSpan:TimeSpan.Zero,
                ConnectCallback=async(context,cancel)=>{
                    if(context.DnsEndPoint.Host!=Target.Host || context.DnsEndPoint.Port!=443)
                        throw new IOException("PERFORMANCE_ORIGIN_MISMATCH");
                    var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                    try{
                        await socket.ConnectAsync(new IPEndPoint(target,443),cancel);
                        Interlocked.Increment(ref connections);
                        return new NetworkStream(socket,ownsSocket:true);
                    }catch{socket.Dispose();throw;}
                }
            };
            using var client=new HttpClient(handler){Timeout=Timeout.InfiniteTimeSpan};
            async Task<long?> Observe()
            {
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(4));
                (IPAddress IP,long Time) result;
                try{result=await Trace(client,reuse,timeout.Token);}
                catch(Exception error)when(error is HttpRequestException or IOException or OperationCanceledException){return null;}
                if(allowedExits.Contains(result.IP.ToString())!=tunneled){
                    Console.WriteLine("WINDOWS_PERF_HTTPS_EXIT_MISMATCH="+route);
                    throw new IOException("WINDOWS_PERF_HTTPS_EXIT_MISMATCH");
                }
                return result.Time;
            }

            // A keepalive sample qualifies only if the request did not open a socket.
            if(reuse)await Observe();
            while(attempts<Samples && !deadline.IsCancellationRequested){
                attempts++;
                int before=Volatile.Read(ref connections);
                long? measurement=await Observe();
                bool reused=Volatile.Read(ref connections)==before;
                if(measurement is long elapsed && reused==reuse)samples.Add(elapsed);
            }
        }

        long? p95=samples.Count==Samples?samples.Order().ElementAt((Samples*95+99)/100-1):null;
        Console.WriteLine("WINDOWS_PERF_HTTPS="+JsonSerializer.Serialize(new{
            route,endpoint=Target.AbsoluteUri,pinned_destination_ipv4=target?.ToString(),family="ipv4",protocol="http/1.1",
            connection=reuse?"reused":"fresh",timing="first_body_byte",dns_included=false,
            required_samples=Samples,attempts,valid_samples=samples.Count,tcp_connections=connections,
            samples_ms=samples,p95_ms=p95,target_ms=TargetMs,under_target=p95 is long observed && observed<TargetMs
        }));
    }

    private static async Task<(IPAddress IP,long Time)> Trace(HttpClient client,bool reuse,CancellationToken cancel)
    {
        using var request=new HttpRequestMessage(HttpMethod.Get,Target){
            Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact
        };
        if(!reuse)request.Headers.ConnectionClose=true;
        request.Headers.CacheControl=new CacheControlHeaderValue{NoCache=true,NoStore=true};
        var timer=Stopwatch.StartNew();
        using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancel);
        response.EnsureSuccessStatusCode();
        await using var stream=await response.Content.ReadAsStreamAsync(cancel);
        byte[] body=new byte[TraceLimit+1];
        int length=await stream.ReadAsync(body.AsMemory(0,1),cancel);
        long elapsed=timer.ElapsedMilliseconds;
        while(length>0 && length<body.Length){
            int count=await stream.ReadAsync(body.AsMemory(length),cancel);
            if(count==0)break;
            length+=count;
        }
        var address=Encoding.ASCII.GetString(body,0,length).Split('\n').Where(line=>line.StartsWith("ip=",StringComparison.Ordinal)).Take(2).ToArray();
        if(length==0 || length>TraceLimit || address.Length!=1 ||
            !IPAddress.TryParse(address[0][3..].Trim(),out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork)
            throw new IOException("WINDOWS_PERF_HTTPS_INVALID_TRACE");
        return (ip,elapsed);
    }
}
