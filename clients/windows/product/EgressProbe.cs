using System.Diagnostics;
namespace OracleProxy.Product;

internal static class EgressProbe
{
    // Keep one HTTP request alive when this generation has received a WG reply.
    // The outer HTTP/3 200 alone does not qualify. A silent carrier retains its
    // short deadline; progress can extend the total budget only up to 12 seconds.
    internal static async Task<long> Verify(HttpClient client,int seconds,Func<bool> replyReceived,CancellationToken stop)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        var timer=Stopwatch.StartNew();
        async Task Read()
        {
            try{
                using var response=await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace",HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                response.EnsureSuccessStatusCode();await using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);
                using var memory=new MemoryStream();var buffer=new byte[1024];int read;
                while((read=await stream.ReadAsync(buffer,deadline.Token))>0){if(memory.Length+read>8192)throw new IOException("ORACLE_EGRESS_NOT_VERIFIED");memory.Write(buffer,0,read);}
                string body=System.Text.Encoding.UTF8.GetString(memory.ToArray());
                if(!body.Split('\n').Any(line=>line=="ip=152.67.156.100"))throw new IOException("ORACLE_EGRESS_NOT_VERIFIED");
            }
            catch(OperationCanceledException error) when(!stop.IsCancellationRequested){throw new IOException("ORACLE_PROBE_TIMEOUT",error);}
            catch(HttpRequestException error){throw new IOException("ORACLE_PROBE_HTTP_FAILED",error);}
        }
        Task pending=Read();bool extended=seconds>=12;
        while(!pending.IsCompleted){
            if(!extended && replyReceived()){
                TimeSpan left=TimeSpan.FromSeconds(12)-timer.Elapsed;
                deadline.CancelAfter(left>TimeSpan.Zero?left:TimeSpan.Zero);extended=true;
            }
            await Task.WhenAny(pending,Task.Delay(25));
        }
        await pending;return timer.ElapsedMilliseconds;
    }
}
