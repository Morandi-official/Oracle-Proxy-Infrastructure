using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Math.EC.Rfc7748;
namespace OracleProxy.Product;
internal sealed class VpnRuntime : IDisposable
{
    private DurableState _secret=null!;
    private readonly AccountApi _api=new();
    private readonly CoreProcess _core=new();
    private readonly SemaphoreSlim _gate=new(1,1);
    private JsonObject? _state;
    private UuInventory? _uuInventory;
    private DateTimeOffset _received;
    private string _mode="starting",_error="";
    private long? _latency;
    private DateTimeOffset _probed;
    private string _runningProfile="";
    private string Profile()=>Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_state!["tunnel"]!.ToJsonString())));
    internal async Task Initialize()
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        Platform.VerifyProtected(Platform.Root);Platform.VerifyProtected(Platform.StateRoot);Platform.VerifyBundle(Platform.Root);
        bool missing=!File.Exists(Path.Combine(Platform.StateRoot,"state.dpapi"));
        _secret=DurableState.Load();
        if(missing && NativeGuard.Active){
            // A lost state file is not an explicit Off request. Keep the last
            // persistent policy (including existing UU exceptions) and require
            // local recovery rather than opening ordinary application egress.
            _secret.ConnectIntent=true;_secret.RecoveryRequired=true;_secret.Save();
            _mode="recovery";_error="STATE_MISSING_RECOVERY_REQUIRED";return;
        }
        if(_secret.ConnectIntent){NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());_mode="protected";}
        else{await EnsureTunnelGone();NativeGuard.Clear();_mode="disconnected";}
    }
    internal async Task Run(CancellationToken cancel)
    {
        while(!cancel.IsCancellationRequested){
            await _gate.WaitAsync(cancel);
            try{
                if(_secret.ConnectIntent && !NativeGuard.Active){
                    _secret.RecoveryRequired=true;_secret.Save();_mode="recovery";_error="WFP_POLICY_LOST";
                    await _core.Stop();NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());
                }
                if(_secret.Token.Length>0){
                    try{await Refresh();
                        if(_secret.ConnectIntent && !_secret.RecoveryRequired){
                            if(ActivePolicy()){
                                if(_core.Running && (_runningProfile!=Profile() || !NativeGuard.TunPermitted))await _core.Stop();
                                if(!_core.Running)await StartCore();
                                else if(DateTimeOffset.UtcNow-_probed>TimeSpan.FromSeconds(15))await Probe();
                            }else{_latency=null;_mode="protected";}
                        }
                    }catch(Exception e){_error=Code(e);if(_secret.ConnectIntent){if(!NativeGuard.Active)await _core.Stop();_mode="protected";_latency=null;}}
                }
            }finally{_gate.Release();}
            await Task.Delay(5000,cancel);
        }
    }
    private async Task Refresh(){_state=await _api.Call("state",_secret.Token);_received=DateTimeOffset.UtcNow;_error="";}
    private bool ActivePolicy()=>_state?["account"]?["status"]?.GetValue<string>()=="active" && _state["observed_at"]?.GetValue<long>() is long at && Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-at)<=20;
    private async Task Probe(){_latency=await _core.Probe();_probed=DateTimeOffset.UtcNow;_mode="connected";}
    private async Task StartCore()
    {
        if(!ActivePolicy())throw new IOException("ACCOUNT_NOT_ACTIVE");
        if(_secret.UuPaths.Any(path=>!UuDiscovery.Trusted(path)))throw new IOException("UU_TRUST_CHANGED_REFRESH_REQUIRED");
        await EnsureTunnelGone();
        NativeGuard.Apply(_secret.UuPaths);
        _mode="connecting";
        try{
            await _core.Start(_state!,_secret);
            NativeGuard.Apply(_secret.UuPaths,NativeGuard.TunLuid(),_core.Pid);
            await Probe();_runningProfile=Profile();
        }catch{await _core.Stop();_mode="protected";throw;}
    }
    internal async Task<JsonObject> Command(JsonObject value)
    {
        if(!value.TryGetPropertyValue("version",out var version)||version?.GetValue<int>()!=1)throw new IOException("INVALID_PROTOCOL");
        string command=value["command"]?.GetValue<string>() ?? "";
        var fields=command=="Login"?new[]{"version","command","username","password"}:new[]{"version","command"};
        if(value.Count!=fields.Length || fields.Any(field=>!value.ContainsKey(field)))throw new IOException("INVALID_FIELDS");
        if(command is not ("Status" or "Login" or "Connect" or "Disconnect" or "Logout" or "RefreshUu"))throw new IOException("UNKNOWN_COMMAND");
        await _gate.WaitAsync();
        try{
            switch(command){
            case "Login":
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_LOGIN");
                string username=value["username"]!.GetValue<string>(),password=value["password"]!.GetValue<string>();
                if(username.Length is <3 or >64 || password.Length is <1 or >128)throw new IOException("INVALID_CREDENTIALS");
                if(_secret.PrivateKey.Length==0){
                    byte[] key=RandomNumberGenerator.GetBytes(32),pub=new byte[32];key[0]&=248;key[31]&=127;key[31]|=64;
                    try{X25519.GeneratePublicKey(key,0,pub,0);_secret.PrivateKey=Convert.ToBase64String(key);_secret.PublicKey=Convert.ToBase64String(pub);_secret.Save();}
                    finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(pub);}
                }
                var login=await _api.Call("login","",new JsonObject{["username"]=username,["password"]=password,["public_key"]=_secret.PublicKey,["device_name"]=Environment.MachineName});
                _secret.Token=login["token"]!.GetValue<string>();login.Remove("token");_secret.Save();_state=login;_received=DateTimeOffset.UtcNow;_error="";break;
            case "Connect":{
                if(_secret.Token.Length==0)throw new IOException("LOGIN_REQUIRED");
                if(_secret.RecoveryRequired)throw new IOException("RECOVERY_REQUIRED");
                if(_core.Running && _mode=="connected")break;
                using var uuMaintenance=UuAclRepair.AcquireMaintenance();
                var inventory=UuDiscovery.Discover();_uuInventory=inventory;
                if(inventory.Candidates>0 && inventory.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                _secret.UuPaths=inventory.Paths;_secret.ConnectIntent=true;_secret.Save();
                NativeGuard.Apply(_secret.UuPaths);_mode="protected";
                await Refresh();await StartCore();break;}
            case "Disconnect":await Disconnect();break;
            case "Logout":
                await Disconnect();
                if(_secret.Token.Length>0){try{await _api.Call("logout",_secret.Token,new JsonObject());}catch{ /* expire remotely; locally erase bearer regardless */ }}
                _secret.Token="";_secret.Save();_state=null;break;
            case "RefreshUu":
                var found=UuDiscovery.Discover();_uuInventory=found;
                if(found.Candidates>0 && found.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_UU_REFRESH");
                _secret.UuPaths=found.Paths;_secret.Save();break;
            }
            return Snapshot();
        }catch(Exception e){_error=Code(e);if(_secret.ConnectIntent){if(!NativeGuard.Active)await _core.Stop();_latency=null;_mode="protected";}return Snapshot(false);}
        finally{_gate.Release();}
    }
    private async Task Disconnect()
    {
        try{
            await _core.Stop();await EnsureTunnelGone();
            _secret.ConnectIntent=false;_secret.RecoveryRequired=false;_secret.Save();
            NativeGuard.Clear();_mode="disconnected";_error="";_latency=null;
        }catch{
            _secret.ConnectIntent=true;_secret.RecoveryRequired=true;_secret.Save();
            try{NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());}catch{}
            _mode="recovery";throw new IOException("RECOVERY_REQUIRED");
        }
    }
    internal static async Task EnsureTunnelGone()
    {
        for(int i=0;i<30;i++){
            if(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy"))return;
            await Task.Delay(100);
        }
        throw new IOException("OWNED_TUNNEL_CLEANUP_NOT_VERIFIED");
    }
    private JsonObject Snapshot(bool ok=true)=>new(){["ok"]=ok,["schema"]=1,["mode"]=_secret.ConnectIntent && !NativeGuard.Active?"recovery":_mode=="connected" && !NativeGuard.TunPermitted?"protected":_mode,["error"]=_error,["intent"]=_secret.ConnectIntent,["guard"]=_secret.ConnectIntent?NativeGuard.Active:false,["latency_ms"]=_latency,["received_at"]=_received==default?null:_received.ToUnixTimeSeconds(),["observed_at"]=_state?["observed_at"]?.DeepClone(),["account"]=_state?["account"]?.DeepClone(),["period"]=_state?["period"]?.DeepClone(),["uu_verified_programs"]=_secret.UuPaths.Length,
        ["product_version"]=typeof(VpnRuntime).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion,
        ["uu_candidates"]=_uuInventory?.Candidates,["uu_rejected"]=_uuInventory?.Rejected,
        ["uu_diagnostics"]=new JsonArray((_uuInventory?.Issues ?? []).Select(issue=>(JsonNode?)new JsonObject{["path"]=issue.Path,["code"]=issue.Code,["detail"]=issue.Detail}).ToArray())};
    private static string Code(Exception e)=>e.Message.Length<=80 && e.Message.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')?e.Message:"SERVICE_OPERATION_FAILED";
    internal void BeginStop(){_api.Cancel();_core.Cancel();}
    public void Dispose(){_core.Dispose();_api.Dispose();_gate.Dispose();}
}
