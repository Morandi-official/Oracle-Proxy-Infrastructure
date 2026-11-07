using System.Text.Json.Nodes;

namespace OracleProxy.Product;

// Only an explicit password login may replace a revoked local identity. The
// server still authenticates the password, enforces quota and keeps tombstones.
internal static class LoginAdmission
{
    internal static async Task<JsonObject> Run(
        Func<string,string,JsonObject?,Task<JsonObject>> call,Func<string> publicKey,
        Action replaceIdentity,string username,string password,string deviceName)
    {
        JsonObject Body()=>new(){["username"]=username,["password"]=password,
            ["public_key"]=publicKey(),["device_name"]=deviceName,["client_version"]=DeviceRegistration.Version};
        long started=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        JsonObject login;
        try{login=await call("authenticate","",Body());}
        catch(ApiException error) when(error.Message=="DEVICE_REVOKED"){
            // A deleted key must never be reinstated. Generate and durably save
            // one new identity, then authenticate it with the same credentials.
            replaceIdentity();
            login=await call("authenticate","",Body());
        }
        string token=login["token"]?.GetValue<string>() ?? throw new IOException("INVALID_API_RESPONSE");
        if(!DeviceRegistration.Confirmed(login)){
            var registered=await call("enroll",token,new JsonObject{["device_name"]=deviceName,["confirm"]=true});
            if(!DeviceRegistration.Confirmed(registered))throw new IOException("DEVICE_CONFIRMATION_REQUIRED");
            registered["token"]=token;
            // The enroll endpoint extends to 30 days; older servers omit the
            // expiry field. Use the earlier request start as a conservative bound.
            registered["token_expires_at"] ??= started+LoginPolicy.MaximumAge;
            login=registered;
        }
        return login;
    }
    internal static bool DashboardReady(JsonObject state)=>
        state["login_authenticated"]?.GetValue<bool>()==true && state["account"] is JsonObject &&
        state["device_registered"]?.GetValue<bool>()==true && state["registration"]?["status"]?.GetValue<string>()=="registered";
}
