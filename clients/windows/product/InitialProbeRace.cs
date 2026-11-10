using System.Net;
using System.Net.Sockets;
namespace OracleProxy.Product;
internal sealed record VerifiedExit(string Address,long ElapsedMs,string Protocol);
internal static class InitialProbeRace
{
    internal static VerifiedExit? Parse(string? line,IReadOnlySet<string> expected,long elapsed)
    {
        const string prefix="EGRESS_H3_VERIFIED ";
        if(line is null || line.Length>160 || !line.StartsWith(prefix,StringComparison.Ordinal))return null;
        var values=line[prefix.Length..].Split(' ');
        if(values.Length!=2 || !IPAddress.TryParse(values[0],out var v4) || v4.AddressFamily!=AddressFamily.InterNetwork || !expected.Contains(v4.ToString()) ||
            !IPAddress.TryParse(values[1],out var v6) || v6.AddressFamily!=AddressFamily.InterNetworkV6 || v6.ScopeId!=0 || v6.ToString()!="2603:c020:c015:8100::10")return null;
        return new VerifiedExit(v4.ToString(),elapsed,"h3");
    }
    internal static async Task<VerifiedExit> Verify(Task<VerifiedExit?>? accelerated,Func<CancellationToken,Task<VerifiedExit>> fallback,CancellationToken stop)
    {
        using var losing=CancellationTokenSource.CreateLinkedTokenSource(stop);
        Task<VerifiedExit> tcp=fallback(losing.Token);
        try{
            if(accelerated is null)return await tcp;
            Task first=await Task.WhenAny((Task)accelerated,tcp).WaitAsync(stop);
            if(first==tcp){
                try{return await tcp;}
                catch when(!stop.IsCancellationRequested){if(await accelerated.WaitAsync(stop) is VerifiedExit late)return late;throw;}
            }
            if(await accelerated.WaitAsync(stop) is VerifiedExit fast)return fast;
            return await tcp;
        }finally{
            losing.Cancel();
            // An HTTP handler that ignores cancellation cannot delay the UI or
            // shutdown. Observe its failure and never accept a late proof.
            _=tcp.ContinueWith(t=>{_=t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
}
