using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal static class ServiceBootstrap
{
    internal static bool Current(JsonObject state,string version)=>
        state["schema"]?.GetValue<int>()==1 && state["ok"]?.GetValue<bool>()==true &&
        state["product_version"]?.GetValue<string>()==version &&
        state["login_authenticated"] is JsonValue proof && proof.TryGetValue<bool>(out _);

    internal static async Task<JsonObject> Ensure(string version,Func<CancellationToken,Task<JsonObject>> read,
        Func<CancellationToken,Task<int>> install,CancellationToken cancel)
    {
        try{var present=await read(cancel);if(Current(present,version))return present;}
        catch(Exception error)when(error is IOException or TimeoutException){}
        cancel.ThrowIfCancellationRequested();
        int result=await install(cancel);
        if(result==4)throw new IOException("SERVICE_SETUP_CANCELLED");
        if(result!=0)throw new IOException("SERVICE_SETUP_FAILED");
        for(int attempt=0;attempt<12;attempt++){
            cancel.ThrowIfCancellationRequested();
            try{var state=await read(cancel);if(Current(state,version))return state;}
            catch(Exception error)when(error is IOException or TimeoutException){}
            await Task.Delay(250,cancel);
        }
        throw new IOException("SERVICE_VERSION_NOT_VERIFIED");
    }
}
