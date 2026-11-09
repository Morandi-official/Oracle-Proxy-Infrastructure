using System.Text.Json.Nodes;
using OracleProxy.Product;
internal static class RecentAccountProofTests
{
    internal static void Run()
    {
        string token="test-token",key="public-test-key",scope=RecentAccountProof.Scope(token);
        var proof=new JsonObject{["observed_at"]=1000L,["registration"]=new JsonObject{["status"]="registered",["device_id"]=RecentAccountProof.Scope(key).ToLowerInvariant()[..12]},["device"]=new JsonObject{["registered"]=true},["tunnel"]=new JsonObject(),["account"]=new JsonObject{["status"]="active"}};
        JsonObject? Read(JsonObject p=default!,string t="test-token",string k="public-test-key",bool live=true,bool auth=true,bool intent=false,bool recovery=false,long now=1001)=>RecentAccountProof.Restore(p??proof,scope,t,k,live,auth,intent,recovery,now);
        var restored=Read()??throw new Exception("FRESH_BOUND_PROOF_REFUSED");
        restored["observed_at"]=999L;if(proof["observed_at"]!.GetValue<long>()!=1000)throw new Exception("PROOF_ALIASED");
        if(Read(now:1020) is null || Read(now:1021) is not null || Read(now:999) is not null || Read(t:"different") is not null || Read(k:"different") is not null || Read(live:false) is not null || Read(auth:false) is not null || Read(intent:true) is not null || Read(recovery:true) is not null)throw new Exception("UNTRUSTED_OR_EXPIRED_PROOF_RESTORED");
        foreach(string status in new[]{"disabled","quota","expired","unavailable"}){
            var bad=(JsonObject)proof.DeepClone();bad["account"]!["status"]=status;if(Read(bad) is not null)throw new Exception("INACTIVE_ACCOUNT_RESTORED");
        }
        Console.WriteLine("RECENT_PROOF_EXACT_IDENTITY_SAME_CONTROLLER_AUTHORITY_WINDOW_AND_FAILURES=PASS");
    }
}
