using System.Text.Json.Nodes;
using OracleProxy.Product;

internal static class LoginAdmissionTests
{
    private static JsonObject State(bool ready)=>new(){["account"]=new JsonObject{["status"]="active"},["registration"]=new JsonObject{["status"]=ready?"registered":"pending"},["device"]=new JsonObject{["registered"]=ready},["tunnel"]=ready?new JsonObject():null};
    private static JsonObject Login(bool ready){var value=State(ready);value["token"]="synthetic-token";value["token_expires_at"]=DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();return value;}
    private static void Check(bool ok){if(!ok)throw new Exception("LOGIN_ADMISSION_REGRESSION");}
    internal static async Task Run()
    {
        foreach(bool existing in new[]{true,false}){
            var actions=new List<string>();int rotates=0;
            var result=await LoginAdmission.Run((action,token,body)=>{
                actions.Add(action);Check(body is not null);
                if(action=="authenticate"){Check(token=="" && body!["public_key"]!.GetValue<string>()=="existing-key");return Task.FromResult(Login(existing));}
                Check(action=="enroll" && token=="synthetic-token" && body!["confirm"]!.GetValue<bool>());return Task.FromResult(State(true));
            },()=>"existing-key",()=>rotates++,"account","password","PC");
            Check(DeviceRegistration.Confirmed(result) && result["token"]!.GetValue<string>()=="synthetic-token" && rotates==0 && actions.SequenceEqual(existing?new[]{"authenticate"}:new[]{"authenticate","enroll"}));
        }
        foreach(string failure in new[]{"INVALID_CREDENTIALS","DEVICE_LIMIT_REACHED","CONTROL_SERVICE_UNAVAILABLE"}){
            int calls=0,rotates=0;
            try{await LoginAdmission.Run((action,_,_)=>{calls++;throw new ApiException(failure);},()=>"key",()=>rotates++,"u","p","PC");throw new Exception("FAILURE_ACCEPTED");}
            catch(ApiException error){Check(error.Message==failure && calls==1 && rotates==0);}
        }
        {
            int auth=0,rotates=0;string key="revoked-key";
            var result=await LoginAdmission.Run((action,_,body)=>{
                if(action=="authenticate"){
                    auth++;if(auth==1)throw new ApiException("DEVICE_REVOKED");
                    Check(body!["public_key"]!.GetValue<string>()=="new-key");return Task.FromResult(Login(false));
                }
                return Task.FromResult(State(true));
            },()=>key,()=>{rotates++;key="new-key";},"u","p","PC");
            Check(rotates==1 && auth==2 && DeviceRegistration.Confirmed(result));
        }
        {
            int rotations=0,calls=0;
            try{await LoginAdmission.Run((_,_,_)=>{calls++;throw new ApiException("DEVICE_REVOKED");},()=>"key",()=>rotations++,"u","p","PC");throw new Exception("UNBOUNDED_ROTATION");}
            catch(ApiException){Check(rotations==1 && calls==2);}
        }
        foreach(string failure in new[]{"ACCOUNT_UNAVAILABLE","DEVICE_REVOKED"}){
            try{await LoginAdmission.Run((action,_,_)=>action=="authenticate"?Task.FromResult(Login(false)):throw new ApiException(failure),()=>"key",()=>throw new Exception("MUST_NOT_ROTATE_ON_ENROLL"),"u","p","PC");throw new Exception("QUOTA_BYPASSED");}
            catch(ApiException error){Check(error.Message==failure);}
        }
        {
            var quotaPending=await LoginAdmission.Run((action,_,_)=>action=="authenticate"?Task.FromResult(Login(false)):throw new ApiException("DEVICE_LIMIT_REACHED"),()=>"key",()=>throw new Exception("MUST_NOT_ROTATE"),"u","p","PC");
            Check(!DeviceRegistration.Confirmed(quotaPending) && quotaPending["token"]!.GetValue<string>()=="synthetic-token" && quotaPending["admission_error"]!.GetValue<string>()=="DEVICE_LIMIT_REACHED");
        }
        try{await LoginAdmission.Run((action,_,_)=>Task.FromResult(action=="authenticate"?Login(false):State(false)),()=>"key",()=>{},"u","p","PC");throw new Exception("UNCONFIRMED_ACCEPTED");}
        catch(IOException error){Check(error.Message=="DEVICE_CONFIRMATION_REQUIRED");}
        var pending=new JsonObject{["login_authenticated"]=true,["account"]=new JsonObject(),["device_registered"]=false,["registration"]=new JsonObject{["status"]="pending"}};
        Check(!LoginAdmission.DashboardReady(pending));pending["device_registered"]=true;Check(!LoginAdmission.DashboardReady(pending));pending["registration"]!["status"]="registered";Check(LoginAdmission.DashboardReady(pending));
        Console.WriteLine("LOGIN_REGISTER_BEFORE_DASHBOARD_QUOTA_REVOCATION_AND_REUSE=PASS");
    }
#if ADMISSION_TESTS
    private static async Task Main()=>await Run();
#endif
}
#if ADMISSION_TESTS
namespace OracleProxy.Product {
    internal sealed class ApiException(string code):Exception(code);
    internal sealed class DurableState {
        public string Token="",RememberedUsername="";
        public long LoginIssuedAt,SessionExpiresAt,RememberLoginUntil;
    }
}
#endif
