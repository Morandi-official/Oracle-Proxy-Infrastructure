using OracleProxy.Product;
internal static class InitialProbeRaceTests
{
    internal static async Task Run()
    {
        static void Check(bool ok){if(!ok)throw new IOException("INITIAL_PROBE_RACE_REGRESSION");}
        var allowed=new HashSet<string>{"152.67.154.225"};
        foreach(string line in new[]{"prefix EGRESS_H3_VERIFIED 152.67.154.225 2603:c020:c015:8100::10","EGRESS_H3_VERIFIED 192.0.2.2 2603:c020:c015:8100::10","EGRESS_H3_VERIFIED 152.67.154.225 2603:c020:c015:8100::11","EGRESS_H3_VERIFIED 152.67.154.225 2603:c020:c015:8100::10 extra","EGRESS_H3_VERIFIED 152.67.154.225 2603:c020:c015:8100::10%1"})
            Check(InitialProbeRace.Parse(line,allowed,12) is null);
        var h3=InitialProbeRace.Parse("EGRESS_H3_VERIFIED 152.67.154.225 2603:c020:c015:8100::10",allowed,12)!;
        Check(h3 is not null);
        var cancelled=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var won=await InitialProbeRace.Verify(Task.FromResult<VerifiedExit?>(h3),async token=>{
            try{await Task.Delay(Timeout.Infinite,token);throw new IOException();}
            finally{cancelled.TrySetResult();}
        },CancellationToken.None);
        Check(won.Protocol=="h3");await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var tcp=new VerifiedExit("152.67.154.225",20,"https");
        Check(await InitialProbeRace.Verify(Task.FromResult<VerifiedExit?>(null),_=>Task.FromResult(tcp),CancellationToken.None)==tcp);
        Check(await InitialProbeRace.Verify(Task.FromResult<VerifiedExit?>(h3),_=>Task.FromException<VerifiedExit>(new IOException()),CancellationToken.None)==h3);
        var pending=new TaskCompletionSource<VerifiedExit?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Check(await InitialProbeRace.Verify(pending.Task,_=>Task.FromResult(tcp),CancellationToken.None)==tcp);
        pending.SetResult(h3);
        try{await InitialProbeRace.Verify(Task.FromResult<VerifiedExit?>(null),_=>Task.FromException<VerifiedExit>(new IOException("EXPECTED")),CancellationToken.None);throw new Exception();}
        catch(IOException error)when(error.Message=="EXPECTED"){}
        using var stop=new CancellationTokenSource(20);
        var silence=new TaskCompletionSource<VerifiedExit?>(TaskCreationOptions.RunContinuationsAsynchronously);
        try{await InitialProbeRace.Verify(silence.Task,async token=>{await Task.Delay(Timeout.Infinite,token);return tcp;},stop.Token);throw new Exception();}
        catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        Console.WriteLine("INITIAL_H3_PROOF_REQUIRES_BOTH_EXPECTED_FAMILIES_ONE_USE_AND_TCP_FALLBACK_WITH_CANCELLED_LOSER=PASS");
    }
}
