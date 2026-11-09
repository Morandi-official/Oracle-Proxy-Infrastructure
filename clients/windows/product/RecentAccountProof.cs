using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;
// Optional SYSTEM-DPAPI proof survives only a deliberate backend stop while
// the exact same GUI owner remains alive. It never extends the existing 20s
// active-policy window, and never skips tunnel/WFP/dual-stack egress checks.
internal static class RecentAccountProof
{
    internal static string Scope(string token)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    internal static JsonObject? Restore(JsonObject? state,string scope,string token,string publicKey,bool sameController,bool authorized,bool intent,bool recovery,long now)
    {
        if(now<=0 || !sameController || !authorized || intent || recovery || state is null || token.Length==0 || publicKey.Length==0 || scope!=Scope(token))return null;
        try{
            if(!DeviceRegistration.Confirmed(state) || state["account"]?["status"]?.GetValue<string>()!="active" ||
               state["observed_at"] is not JsonValue stamp || !stamp.TryGetValue<long>(out long at) || at<=0 || at>now || now-at>20)return null;
            string id=Scope(publicKey).ToLowerInvariant()[..12];
            if(state["registration"]?["device_id"]?.GetValue<string>()!=id)return null;
            return (JsonObject)state.DeepClone();
        }catch(Exception error)when(error is InvalidOperationException or FormatException or ArgumentException){return null;}
    }
}
