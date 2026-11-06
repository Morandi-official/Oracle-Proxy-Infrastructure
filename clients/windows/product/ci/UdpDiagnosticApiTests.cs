using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal static class UdpDiagnosticApiTests
{
    internal static async Task Run()
    {
        int calls=0;
        var timedOut=new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        var result=UdpDiagnosticApi.Call(()=>{calls++;return timedOut.Task;},CancellationToken.None);
        timedOut.SetException(new TaskCanceledException("SYNTHETIC_PRIVATE_REQUEST_DETAIL"));
        try{await result;throw new Exception("API_TIMEOUT_NOT_DETECTED");}
        catch(IOException error)when(error.Message=="DIAGNOSTIC_API_TIMEOUT"){}
        if(calls!=1)throw new Exception("NON_IDEMPOTENT_REQUEST_RETRIED");

        using var stop=new CancellationTokenSource();
        var cancelled=new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        result=UdpDiagnosticApi.Call(()=>cancelled.Task,stop.Token);
        stop.Cancel();cancelled.SetCanceled(stop.Token);
        try{await result;throw new Exception("CANCEL_NOT_PROPAGATED");}
        catch(OperationCanceledException){}
        calls=0;
        try{await UdpDiagnosticApi.Call(()=>{calls++;return Task.FromResult(new JsonObject());},stop.Token);throw new Exception("STOPPED_REQUEST_DISPATCHED");}
        catch(OperationCanceledException){}
        if(calls!=0)throw new Exception("STOPPED_REQUEST_DISPATCHED");

        var expected=new JsonObject{["diagnostic_id"]="synthetic"};
        if(!ReferenceEquals(expected,await UdpDiagnosticApi.Call(()=>Task.FromResult(expected),CancellationToken.None)))
            throw new Exception("SUCCESS_RESPONSE_CHANGED");
        var denied=new IOException("DIAGNOSTIC_ACCOUNT_NOT_ACTIVE");
        try{await UdpDiagnosticApi.Call(()=>Task.FromException<JsonObject>(denied),CancellationToken.None);throw new Exception("POLICY_ERROR_SWALLOWED");}
        catch(IOException error)when(ReferenceEquals(error,denied)){}
        Console.WriteLine("UDP_API_TIMEOUT_IS_FAILURE_CANCEL_IS_CANCEL_NO_MUTATING_RETRY=PASS");
    }
}
