using System.Text.Json.Nodes;
namespace OracleProxy.Product;

// AccountApi has its own bounded request token. Its expiry is a transport
// failure, not a request by the user to cancel the entire diagnostic.
internal static class UdpDiagnosticApi
{
    internal static async Task<JsonObject> Call(Func<Task<JsonObject>> request,CancellationToken stop)
    {
        stop.ThrowIfCancellationRequested();
        try{return await request();}
        catch(OperationCanceledException error)when(!stop.IsCancellationRequested){
            // Never retry start/begin/sample: the server may have processed a
            // request whose response was lost. Keep the partial observations.
            throw new IOException("DIAGNOSTIC_API_TIMEOUT",error);
        }
    }
}
