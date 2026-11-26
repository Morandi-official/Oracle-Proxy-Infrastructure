using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

// Non-shipped data-plane fixture. A completed STUN transaction measures a real
// UDP request and response, even with a local TUN TCP stack accepting SYNs.
internal static class OracleNetworkPerformance
{
    private const int Samples=12,TargetMs=500,ProbeTimeoutMs=1200;
    private const uint StunCookie=0x2112A442;
    internal sealed record Target(string Host,int Port,IPAddress? Address);
    private sealed record Sample(long Sent,long Finished,double? RttMs);

    internal sealed class DownloadWindow
    {
        private readonly TaskCompletionSource<bool> _started=new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _finished=new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long _first,_last;
        private bool _complete;

        internal Task<bool> Started=>_started.Task;
        internal Task Finished=>_finished.Task;

        internal void BodyChunk()
        {
            long now=Stopwatch.GetTimestamp();
            _last=now;
            if(_first!=0)return;
            _first=now;
            _started.TrySetResult(true);
        }

        internal void Finish(bool complete)
        {
            _complete=complete;
            _started.TrySetResult(false);
            _finished.TrySetResult();
        }

        internal bool Contains(long sent,long finished)=>_complete && _first!=0 && sent>=_first && finished<=_last;
        internal double? DurationMs=>_complete && _first!=0?Stopwatch.GetElapsedTime(_first,_last).TotalMilliseconds:null;
    }

    internal static async Task<Target[]> ResolveTargets() =>
        await Task.WhenAll(Resolve("stun.cloudflare.com",3478),Resolve("stun.l.google.com",19302));

    private static async Task<Target> Resolve(string host,int port)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(4));
        try{return new(host,port,(await Dns.GetHostAddressesAsync(host,AddressFamily.InterNetwork,deadline.Token)).FirstOrDefault());}
        catch(Exception error)when(error is SocketException or OperationCanceledException){return new(host,port,null);}
    }

    internal static async Task Measure(IReadOnlyList<Target> targets,IReadOnlySet<string> allowedExits,
        bool tunneled,int expectedIndex,DownloadWindow? window=null)
    {
        bool started=window is null || await window.Started;
        var series=await Task.WhenAll(targets.Select(target=>MeasureTarget(target,allowedExits,tunneled,expectedIndex,started,window)));
        if(window is not null)await window.Finished;
        for(int i=0;i<targets.Count;i++)Report(targets[i],series[i],tunneled,window);
    }

    private static async Task<Sample[]> MeasureTarget(Target target,IReadOnlySet<string> allowedExits,
        bool tunneled,int expectedIndex,bool started,DownloadWindow? window)
    {
        if(target.Address is not IPAddress address)return [];
        AssertInterface(address,expectedIndex);
        if(!started || window?.Finished.IsCompleted==true)return [];
        using var socket=new UdpClient(AddressFamily.InterNetwork);
        socket.Connect(address,target.Port);
        var result=new List<Sample>(Samples);
        try{
            for(int i=0;i<Samples && window?.Finished.IsCompleted!=true;i++){
                result.Add(await Probe(socket,allowedExits,tunneled));
                if(i+1<Samples && window?.Finished.IsCompleted!=true)await Task.Delay(80);
            }
        }finally{AssertInterface(address,expectedIndex);}
        return result.ToArray();
    }

    private static async Task<Sample> Probe(UdpClient socket,IReadOnlySet<string> allowedExits,bool tunneled)
    {
        byte[] request=new byte[20];
        request[1]=1;
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4),StunCookie);
        RandomNumberGenerator.Fill(request.AsSpan(8));
        using var timeout=new CancellationTokenSource(TimeSpan.FromMilliseconds(ProbeTimeoutMs));
        long sent=Stopwatch.GetTimestamp();
        try{
            await socket.SendAsync(request.AsMemory(),timeout.Token);
            while(true){
                var response=await socket.ReceiveAsync(timeout.Token);
                long received=Stopwatch.GetTimestamp();
                if(MappedAddress(response.Buffer,request) is not IPAddress mapped)continue;
                if(allowedExits.Contains(mapped.ToString())!=tunneled){
                    Console.WriteLine("WINDOWS_PERF_NETWORK_EXIT_MISMATCH="+(tunneled?"wireguard":"direct"));
                    throw new IOException("WINDOWS_PERF_NETWORK_EXIT_MISMATCH");
                }
                return new(sent,received,Stopwatch.GetElapsedTime(sent,received).TotalMilliseconds);
            }
        }catch(Exception error)when(error is SocketException or OperationCanceledException){
            return new(sent,Stopwatch.GetTimestamp(),null);
        }
    }

    private static IPAddress? MappedAddress(ReadOnlySpan<byte> response,ReadOnlySpan<byte> request)
    {
        if(response.Length<20 || BinaryPrimitives.ReadUInt16BigEndian(response)!=0x0101 ||
            !response.Slice(4,16).SequenceEqual(request.Slice(4,16)))return null;
        int body=BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
        if(body%4!=0 || response.Length!=20+body)return null;
        IPAddress? mapped=null;
        Span<byte> encoded=stackalloc byte[4];
        for(int offset=20;offset<response.Length;){
            if(offset+4>response.Length)return null;
            int type=BinaryPrimitives.ReadUInt16BigEndian(response[offset..]);
            int size=BinaryPrimitives.ReadUInt16BigEndian(response[(offset+2)..]);
            offset+=4;
            int padded=(size+3)&~3;
            if(offset+padded>response.Length)return null;
            if(type==0x0020){
                if(size!=8 || response[offset]!=0 || response[offset+1]!=1 || mapped is not null ||
                    (BinaryPrimitives.ReadUInt16BigEndian(response[(offset+2)..])^(StunCookie>>16))==0)return null;
                uint address=BinaryPrimitives.ReadUInt32BigEndian(response[(offset+4)..])^StunCookie;
                BinaryPrimitives.WriteUInt32BigEndian(encoded,address);
                mapped=new IPAddress(encoded);
            }
            offset+=padded;
        }
        return mapped;
    }

    private static void Report(Target target,Sample[] samples,bool tunneled,DownloadWindow? window)
    {
        var qualifying=window is null?samples:samples.Where(s=>window.Contains(s.Sent,s.Finished)).ToArray();
        var timings=qualifying.Where(s=>s.RttMs is not null).Select(s=>s.RttMs!.Value).ToArray();
        var sorted=timings.Order().ToArray();
        double? Percentile(double fraction)=>sorted.Length==0?null:Math.Round(sorted[(int)Math.Ceiling(fraction*sorted.Length)-1],2);
        double? jitter=qualifying.Length<2?null:MeanVariation(qualifying);
        var p95=Percentile(0.95);
        Console.WriteLine("WINDOWS_PERF_UDP_RTT="+JsonSerializer.Serialize(new{
            route=tunneled?"wireguard":"direct",condition=window is null?"idle":"during_download_body",
            endpoint=target.Host,pinned_destination_ipv4=target.Address?.ToString(),port=target.Port,
            protocol="stun_binding_udp",dns_included=false,tls_included=false,
            attempted=samples.Length,qualifying_attempts=qualifying.Length,replies=timings.Length,
            loss_percent=qualifying.Length==0?(double?)null:Math.Round(100d*(qualifying.Length-timings.Length)/qualifying.Length,2),
            samples_ms=qualifying.Select(s=>s.RttMs is double rtt?Math.Round(rtt,2):(double?)null),
            p50_ms=Percentile(0.50),p95_ms=p95,mean_adjacent_rtt_change_ms=jitter,
            download_body_window_ms=window?.DurationMs,target_ms=TargetMs,
            idle_target_met=window is null && timings.Length==Samples && p95 is double measured && measured<TargetMs
        }));
    }

    private static double? MeanVariation(Sample[] samples)
    {
        var changes=samples.Zip(samples.Skip(1),(a,b)=>a.RttMs is double left && b.RttMs is double right?Math.Abs(left-right):(double?)null);
        return changes.Average() is double average?Math.Round(average,2):null;
    }

    private static void AssertInterface(IPAddress address,int expectedIndex)
    {
        uint destination=BinaryPrimitives.ReadUInt32LittleEndian(address.GetAddressBytes());
        uint error=GetBestInterface(destination,out uint actual);
        if(error!=0){Console.WriteLine("WINDOWS_PERF_NETWORK_ROUTE_UNAVAILABLE="+error);throw new IOException("WINDOWS_PERF_NETWORK_ROUTE_UNAVAILABLE",new Win32Exception((int)error));}
        if(actual!=expectedIndex){Console.WriteLine("WINDOWS_PERF_NETWORK_ROUTE_MISMATCH=true");throw new IOException("WINDOWS_PERF_NETWORK_ROUTE_MISMATCH");}
    }

    [DllImport("iphlpapi.dll",ExactSpelling=true)]
    private static extern uint GetBestInterface(uint destination,out uint index);
}
