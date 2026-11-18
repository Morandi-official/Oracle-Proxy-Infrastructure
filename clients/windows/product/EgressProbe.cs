using System.Diagnostics;
namespace OracleProxy.Product;

internal static class EgressProbe
{
    // Retain a slow HTTPS proof after a WireGuard reply and give a stalled
    // request one spare attempt within the same deadline. Only a validated
    // exit address is proof. Silent carriers keep their original behavior.
    internal static async Task<long> Verify(HttpClient client,int seconds,Func<bool> replyReceived,CancellationToken stop,string target="https://www.cloudflare.com/cdn-cgi/trace",string expected="152.67.156.100",IReadOnlySet<string>? allowed=null,Action<string>? observed=null)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        CancellationToken probeToken=deadline.Token;
        var timer=Stopwatch.StartNew();
        async Task<string> Read()
        {
            try{
                using var response=await client.GetAsync(target,HttpCompletionOption.ResponseHeadersRead,probeToken);
                response.EnsureSuccessStatusCode();await using var stream=await response.Content.ReadAsStreamAsync(probeToken);
                using var memory=new MemoryStream();var buffer=new byte[1024];int read;
                while((read=await stream.ReadAsync(buffer,probeToken))>0){if(memory.Length+read>8192)throw new IOException("ORACLE_EGRESS_NOT_VERIFIED");memory.Write(buffer,0,read);}
                string body=System.Text.Encoding.UTF8.GetString(memory.ToArray());
                string? actual=body.Split('\n').Where(line=>line.StartsWith("ip=",StringComparison.Ordinal)).Select(line=>line[3..]).FirstOrDefault();
                if(actual is null || (allowed is null?actual!=expected:!allowed.Contains(actual)))throw new IOException("ORACLE_EGRESS_NOT_VERIFIED");
                return actual;
            }
            catch(OperationCanceledException error) when(!stop.IsCancellationRequested){throw new IOException("ORACLE_PROBE_TIMEOUT",error);}
            catch(HttpRequestException error){throw new IOException("ORACLE_PROBE_HTTP_FAILED",error);}
        }
        Task<string>? first=Read(), spare=null;
        bool extended=seconds>=12;
        bool retryStarted=false;
        try{
            while(first is not null || spare is not null){
                stop.ThrowIfCancellationRequested();
                if(probeToken.IsCancellationRequested)throw new IOException("ORACLE_PROBE_TIMEOUT");

                Task<string>? completed=first?.IsCompleted==true?first:spare?.IsCompleted==true?spare:null;
                if(completed is not null){
                    if(completed==first)first=null;else spare=null;
                    try{
                        string actual=await completed;
                        observed?.Invoke(actual);
                        return timer.ElapsedMilliseconds;
                    }
                    catch(IOException error)when(error.Message=="ORACLE_PROBE_HTTP_FAILED" && (first is not null || spare is not null)){
                        // The other request still has time to return a valid proof.
                    }
                    continue;
                }

                if(replyReceived()){
                    if(!extended){
                        TimeSpan left=TimeSpan.FromSeconds(12)-timer.Elapsed;
                        deadline.CancelAfter(left>TimeSpan.Zero?left:TimeSpan.Zero);extended=true;
                    }
                    if(!retryStarted && timer.Elapsed>=TimeSpan.FromSeconds(6)){
                        retryStarted=true;
                        spare=Read();
                    }
                }
                var tick=Task.Delay(25);
                if(first is not null && spare is not null)await Task.WhenAny(first,spare,tick);
                else await Task.WhenAny((Task?)first??spare!,tick);
            }
            throw new IOException("ORACLE_PROBE_TIMEOUT");
        }finally{
            deadline.Cancel();
            ObserveLateFailure(first);
            ObserveLateFailure(spare);
        }
    }

    private static void ObserveLateFailure(Task? pending)
    {
        if(pending is not null)_=pending.ContinueWith(t=>{_=t.Exception;},CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    }
}
