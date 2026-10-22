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
    private string _stage="IDLE";
    private JsonObject? _failure;
    private TunnelTransport _transport;
    private int _probeFailures;
    private JsonObject? _nativeUdpAttempt;
    private void RecordNativeProbe(bool verified)
    {
        if(_transport!=TunnelTransport.WireGuardUdp || _nativeUdpAttempt is null)return;
        _nativeUdpAttempt["probe_result"]=verified?"oracle_egress_verified":CodeForNativeProbe();
        if(!verified)_nativeUdpAttempt["probe_failures"]=_nativeUdpAttempt["probe_failures"]!.GetValue<int>()+1;
        _nativeUdpAttempt["attempt_elapsed_ms"]=System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted).Ticks/TimeSpan.TicksPerMillisecond;
    }
    private string CodeForNativeProbe()=>_error switch{"ORACLE_PROBE_TIMEOUT"=>"egress_probe_timeout","ORACLE_PROBE_HTTP_FAILED"=>"egress_probe_http_failed",_=>"egress_not_verified"};
    private Task<JsonObject>? _refreshPending;
    private string _refreshToken="";
    private Task<long>? _probePending;
    private uint _probePid;
    private long _generation,_probeGeneration,_verifiedGeneration=-1,_carrierStarted;
    private DateTimeOffset _nextRefresh,_nextProbe,_prepareUntil,_verified;
    private long? _connectMs;
    private JsonObject? _switchTimings;
    private readonly CarrierMemory _carriers=new();
    private DateTimeOffset _nextNetworkCheck;
    private long _clickStarted;
    private long? _readyMs;
    private void MarkConnected(){_mode="connected";if(_clickStarted!=0 && _readyMs is null)_readyMs=System.Diagnostics.Stopwatch.GetElapsedTime(_clickStarted).Ticks/TimeSpan.TicksPerMillisecond;}
    private bool WarmReady=>!_secret.ConnectIntent && _core.Running && !_core.TunActive && _verifiedGeneration==_generation && ActivePolicy() && _runningProfile==Profile() && DateTimeOffset.UtcNow-_verified<TimeSpan.FromSeconds(15);
    private bool Preparing=>!_secret.ConnectIntent && _secret.Token.Length>0 && DateTimeOffset.UtcNow<_prepareUntil;
    private void Failed(Exception error){_error=Code(error);_failure=ConnectionFailure.Capture(_stage,error,_core.SafeStage);if(_stage=="ORACLE_EGRESS_PROBE" && _error is "ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED")_probeFailures++;}
    private long? _latency;
    private string _runningProfile="";
    private string Profile()=>Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_state!["tunnel"]!.ToJsonString())));
    internal async Task Initialize()
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        Platform.VerifyProtected(Platform.Root);Platform.VerifyProtected(Platform.StateRoot);Platform.VerifyBundle(Platform.Root);
        bool missing=!File.Exists(Path.Combine(Platform.StateRoot,"state.dpapi"));
        _secret=DurableState.Load();
        _carriers.Observe(CarrierMemory.Network());
        if(missing && NativeGuard.Active){
            // A lost state file is not an explicit Off request. Keep the last
            // persistent policy (including existing UU exceptions) and require
            // local recovery rather than opening ordinary application egress.
            _secret.ConnectIntent=true;_secret.RecoveryRequired=true;_secret.Save();
            _mode="recovery";_error="STATE_MISSING_RECOVERY_REQUIRED";return;
        }
        if(_secret.ConnectIntent){NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());_mode="protected";}
        else{await EnsureTunnelRemoved();NativeGuard.Clear();_mode="disconnected";}
    }
    internal async Task Run(CancellationToken cancel)
    {
        while(!cancel.IsCancellationRequested){
            await _gate.WaitAsync(cancel);
            try{
                if(_secret.ConnectIntent && !NativeGuard.Active){
                    _secret.RecoveryRequired=true;_secret.Save();_mode="recovery";_error="WFP_POLICY_LOST";
                    await StopCore();NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());
                }
                try{
                    if(DateTimeOffset.UtcNow>=_nextNetworkCheck){
                        _nextNetworkCheck=DateTimeOffset.UtcNow.AddSeconds(1);
                        if(_carriers.Observe(CarrierMemory.Network())){
                            _nativeUdpAttempt=null;await StopCore();_transport=TunnelTransport.WireGuardUdp;_probeFailures=0;
                            if(_secret.ConnectIntent)_mode="protected";
                        }
                    }
                    if(_refreshPending?.IsCompleted==true){
                        var pending=_refreshPending;_refreshPending=null;
                        if(_refreshToken==_secret.Token){_state=await pending;_received=DateTimeOffset.UtcNow;}
                        else{try{await pending;}catch{}}
                    }
                    if(_probePending?.IsCompleted==true){
                        var pending=_probePending;_probePending=null;
                        if(_core.Running && _probePid==_core.Pid && _probeGeneration==_generation){
                            try{
                                _latency=await pending;RecordNativeProbe(true);_verified=DateTimeOffset.UtcNow;_verifiedGeneration=_generation;_failure=null;_probeFailures=0;_error="";
                                if(_secret.ConnectIntent && NativeGuard.TunPermitted)MarkConnected();
                            }catch(Exception error){
                                _verified=default;_stage="ORACLE_EGRESS_PROBE";Failed(error);RecordNativeProbe(false);
                                if(_secret.ConnectIntent){_mode="protected";_latency=null;}
                                if(_error is not ("ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED"))await StopCore();
                            }
                        }else{try{await pending;}catch{}}
                    }
                    if(_secret.Token.Length>0 && _refreshPending is null && DateTimeOffset.UtcNow>=_nextRefresh){
                        _refreshToken=_secret.Token;_refreshPending=_api.Call("state",_refreshToken);_nextRefresh=DateTimeOffset.UtcNow.AddSeconds(5);
                    }
                    if((_secret.ConnectIntent && !_secret.RecoveryRequired) || Preparing){
                        if(!ActivePolicy()){
                            await StopCore();_latency=null;
                            if(_secret.ConnectIntent)_mode="protected";
                        }else{
                            if(_probeFailures>=2 && System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted)>=TimeSpan.FromSeconds(12) && TransportPolicy.Next(_transport,_state!) is TunnelTransport next){
                                _carriers.Failed(_transport);
                                _transport=next;_probeFailures=0;_stage=next==TunnelTransport.WireGuardQuic?"QUIC_FALLBACK":"HTTPS_FALLBACK";await StopCore();
                            }
                            if(_core.Running && (_runningProfile!=Profile() || (_secret.ConnectIntent && !NativeGuard.TunPermitted)))await StopCore();
                            if(!_core.Running){
                                if(!_secret.ConnectIntent){
                                    _stage="UU_DISCOVERY";_uuInventory=UuDiscovery.Discover();
                                    if(_uuInventory.Candidates>0 && _uuInventory.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                                    _secret.UuPaths=_uuInventory.Paths;_secret.Save();
                                }
                                await StartCore(!_secret.ConnectIntent);
                            }
                            if(_probePending is null && DateTimeOffset.UtcNow>=_nextProbe){
                                _stage="ORACLE_EGRESS_PROBE";_probePid=_core.Pid;_probeGeneration=_generation;_probePending=_core.Probe(_verified==default?3:12);
                                _nextProbe=DateTimeOffset.UtcNow.AddSeconds(_verified==default?2:10);
                            }
                        }
                    }else if(!_secret.ConnectIntent && _core.Running){await StopCore();_transport=_state is null?TunnelTransport.WireGuardUdp:_carriers.Preferred(_state);_probeFailures=0;}
                }catch(Exception error){
                    Failed(error);
                    if(_secret.ConnectIntent){if(!NativeGuard.Active)await StopCore();_mode="protected";_latency=null;}
                }
            }finally{_gate.Release();}
            await Task.Delay(200,cancel);
        }
    }
    private async Task StopCore(){_generation++;await _core.Stop();_verified=default;_runningProfile="";_nextProbe=default;}
    private async Task Refresh(){_stage="ACCOUNT_STATE";_state=await _api.Call("state",_secret.Token);_received=DateTimeOffset.UtcNow;_error="";}
    private bool ActivePolicy()=>_state?["account"]?["status"]?.GetValue<string>()=="active" && _state["observed_at"]?.GetValue<long>() is long at && Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-at)<=20;
    private async Task StartCore(bool standby=false,bool guardInstalled=false)
    {
        if(!ActivePolicy())throw new IOException("ACCOUNT_NOT_ACTIVE");
        if(_secret.UuPaths.Any(path=>!UuDiscovery.Trusted(path)))throw new IOException("UU_TRUST_CHANGED_REFRESH_REQUIRED");
        _stage="TUN_CLEANUP";await EnsureTunnelRemoved();
        if(!standby){_stage="GUARD_INSTALL";if(!guardInstalled)NativeGuard.Apply(_secret.UuPaths);_mode="protected";}
        try{
            _stage="CORE_START";_generation++;_verified=default;_verifiedGeneration=-1;_latency=null;_carrierStarted=System.Diagnostics.Stopwatch.GetTimestamp();
            if(_transport==TunnelTransport.WireGuardUdp)_nativeUdpAttempt=new JsonObject{
                ["endpoint_port"]=int.Parse(_state!["tunnel"]!["endpoint"]!.GetValue<string>().Split(':')[1]),
                ["started_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["started_without_tun"]=standby,
                ["socket_binding"]="connected_ipv4",["probe_result"]="pending",["probe_failures"]=0,["attempt_elapsed_ms"]=0};
            await _core.Start(_state!,_secret,_transport,standby:true);
            if(!standby){_stage="TUN_ACTIVATE";await _core.Activate();_stage="TUN_AUTHORIZE";NativeGuard.AuthorizeTun(_core.Pid);}
            _runningProfile=Profile();_nextProbe=default;
        }catch{await StopCore();if(!standby)_mode="protected";throw;}
    }
    internal async Task<JsonObject> Command(JsonObject value)
    {
        if(!value.TryGetPropertyValue("version",out var version)||version?.GetValue<int>()!=1)throw new IOException("INVALID_PROTOCOL");
        string command=value["command"]?.GetValue<string>() ?? "";
        var fields=command=="Login"?new[]{"version","command","username","password"}:new[]{"version","command"};
        if(value.Count!=fields.Length || fields.Any(field=>!value.ContainsKey(field)))throw new IOException("INVALID_FIELDS");
        if(command is not ("Status" or "Login" or "Connect" or "Disconnect" or "Logout" or "RefreshUu" or "Prepare"))throw new IOException("UNKNOWN_COMMAND");
        await _gate.WaitAsync();
        try{
            switch(command){
            case "Prepare":_prepareUntil=DateTimeOffset.UtcNow.AddSeconds(20);break;
            case "Login":
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_LOGIN");
                await StopCore();_transport=TunnelTransport.WireGuardUdp;_probeFailures=0;_nativeUdpAttempt=null;
                _stage="ACCOUNT_LOGIN";string username=value["username"]!.GetValue<string>(),password=value["password"]!.GetValue<string>();
                if(username.Length is <3 or >64 || password.Length is <1 or >128)throw new IOException("INVALID_CREDENTIALS");
                if(_secret.PrivateKey.Length==0){
                    byte[] key=RandomNumberGenerator.GetBytes(32),pub=new byte[32];key[0]&=248;key[31]&=127;key[31]|=64;
                    try{X25519.GeneratePublicKey(key,0,pub,0);_secret.PrivateKey=Convert.ToBase64String(key);_secret.PublicKey=Convert.ToBase64String(pub);_secret.Save();}
                    finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(pub);}
                }
                var login=await _api.Call("login","",new JsonObject{["username"]=username,["password"]=password,["public_key"]=_secret.PublicKey,["device_name"]=Environment.MachineName});
                _secret.Token=login["token"]!.GetValue<string>();login.Remove("token");_secret.Save();_state=login;_received=DateTimeOffset.UtcNow;_error="";break;
            case "Connect":{
                var timer=System.Diagnostics.Stopwatch.StartNew();_connectMs=null;_switchTimings=new JsonObject();
                if(_secret.Token.Length==0)throw new IOException("LOGIN_REQUIRED");
                if(_secret.RecoveryRequired)throw new IOException("RECOVERY_REQUIRED");
                if(_core.Running && _mode=="connected" && _secret.ConnectIntent)break;
                if(_secret.ConnectIntent && _core.Running && NativeGuard.TunPermitted){_nextProbe=default;break;}
                _clickStarted=System.Diagnostics.Stopwatch.GetTimestamp();_readyMs=null;
                bool warm=WarmReady;
                bool reusable=_core.Running && !_core.TunActive && ActivePolicy() && _runningProfile==Profile();
                if(!_secret.ConnectIntent && !reusable){await StopCore();_transport=_state is null?TunnelTransport.WireGuardUdp:_carriers.Preferred(_state);_probeFailures=0;}
                using var uuMaintenance=UuAclRepair.AcquireMaintenance();
                if(_carriers.Observe(CarrierMemory.Network())){await StopCore();_transport=TunnelTransport.WireGuardUdp;_probeFailures=0;warm=false;reusable=false;}
                _stage="UU_DISCOVERY";var inventory=UuDiscovery.Discover();_uuInventory=inventory;_switchTimings["uu_discovery_ms"]=timer.ElapsedMilliseconds;
                if(inventory.Candidates>0 && inventory.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                // Process exceptions are part of the prepared configuration.
                if(reusable && !_secret.UuPaths.SequenceEqual(inventory.Paths,StringComparer.OrdinalIgnoreCase)){await StopCore();warm=false;reusable=false;_transport=_carriers.Preferred(_state!);}
                _secret.UuPaths=inventory.Paths;_secret.ConnectIntent=true;_secret.Save();_switchTimings["state_saved_ms"]=timer.ElapsedMilliseconds;
                _stage="GUARD_INSTALL";NativeGuard.Apply(_secret.UuPaths);_mode="protected";_switchTimings["guard_installed_ms"]=timer.ElapsedMilliseconds;
                if(!warm && !reusable){await Refresh();await StartCore(guardInstalled:true);}
                else{
                    _stage="TUN_ACTIVATE";await _core.Activate();_switchTimings["tun_active_ms"]=timer.ElapsedMilliseconds;_stage="TUN_AUTHORIZE";
                    NativeGuard.AuthorizeTun(_core.Pid);
                    if(warm){MarkConnected();_error="";_failure=null;}
                    _nextProbe=default;
                }
                _connectMs=timer.ElapsedMilliseconds;_switchTimings["complete_ms"]=_connectMs;break;}
            case "Disconnect":await Disconnect();break;
            case "Logout":
                await Disconnect();
                _prepareUntil=default;await StopCore();
                if(_secret.Token.Length>0){try{await _api.Call("logout",_secret.Token,new JsonObject());}catch{ /* expire remotely; locally erase bearer regardless */ }}
                _secret.Token="";_secret.Save();_state=null;break;
            case "RefreshUu":
                _stage="UU_DISCOVERY";var found=UuDiscovery.Discover();_uuInventory=found;
                if(found.Candidates>0 && found.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_UU_REFRESH");
                await StopCore();
                _secret.UuPaths=found.Paths;_secret.Save();break;
            }
            return Snapshot();
        }catch(Exception e){Failed(e);if(_secret.ConnectIntent){if(!NativeGuard.Active)await _core.Stop();_latency=null;_mode="protected";}return Snapshot(false);}
        finally{_gate.Release();}
    }
    private async Task Disconnect()
    {
        try{
            _stage="DISCONNECT";
            bool keep=_core.Running && _core.StandbyCapable && ActivePolicy() && _runningProfile==Profile();
            _stage="DISCONNECT_DEACTIVATE";
            if(keep){if(_core.TunActive)await _core.Deactivate();}
            else await StopCore();
            _stage="DISCONNECT_AUDIT";
            if(keep)await EnsureTunnelInactive();else await EnsureTunnelRemoved();
            _stage="DISCONNECT_STATE";
            _secret.ConnectIntent=false;_secret.RecoveryRequired=false;_secret.Save();
            _stage="DISCONNECT_GUARD_CLEAR";
            NativeGuard.Clear();_mode="disconnected";_error="";_latency=null;_failure=null;_stage="IDLE";_probeFailures=0;
            _prepareUntil=DateTimeOffset.UtcNow.AddSeconds(20);
            if(!keep)_transport=_state is null?TunnelTransport.WireGuardUdp:_carriers.Preferred(_state);
        }catch(Exception error){
            _secret.ConnectIntent=true;_secret.RecoveryRequired=true;_secret.Save();
            try{NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());}catch{}
            _mode="recovery";throw new IOException("RECOVERY_REQUIRED",error);
        }
    }
    internal static async Task EnsureTunnelInactive()
    {
        for(int i=0;i<30;i++){
            if(TunnelInactive() && (!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy") || NativeGuard.TunDormant))return;
            await Task.Delay(100);
        }
        throw new IOException("OWNED_TUNNEL_CLEANUP_NOT_VERIFIED");
    }
    // Only the already-running private core can retain a dormant adapter. A new
    // core must never adopt an unrelated/stale adapter merely by its name.
    internal static async Task EnsureTunnelRemoved()
    {
        for(int i=0;i<30;i++){
            if(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy"))return;
            await Task.Delay(100);
        }
        throw new IOException("OWNED_TUNNEL_REMOVAL_NOT_VERIFIED");
    }
    internal static bool TunnelInactive()=>!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy" &&
        (n.OperationalStatus==OperationalStatus.Up || n.GetIPProperties().UnicastAddresses.Any(a=>!a.Address.IsIPv6LinkLocal)));
    private JsonObject Snapshot(bool ok=true)=>new(){["ok"]=ok,["schema"]=1,["mode"]=_secret.ConnectIntent && !NativeGuard.Active?"recovery":_mode=="connected" && !NativeGuard.TunPermitted?"protected":_mode,["error"]=_error,["intent"]=_secret.ConnectIntent,["guard"]=_secret.ConnectIntent?NativeGuard.Active:false,["latency_ms"]=_latency,["received_at"]=_received==default?null:_received.ToUnixTimeSeconds(),["observed_at"]=_state?["observed_at"]?.DeepClone(),["account"]=_state?["account"]?.DeepClone(),["period"]=_state?["period"]?.DeepClone(),["uu_verified_programs"]=_secret.UuPaths.Length,
        ["failure"]=_failure?.DeepClone(),["connection_stage"]=_stage,["core_stage"]=_core.SafeStage,["core_pid"]=_core.Pid,["tun_permitted"]=_secret.ConnectIntent && NativeGuard.TunPermitted,["transport"]=TransportPolicy.Name(_transport),
        ["server_handshake_at"]=_state?["device"]?["handshake_at"]?.DeepClone(),["peer_rx_bytes"]=_state?["device"]?["usage"]?["rx"]?.DeepClone(),["peer_tx_bytes"]=_state?["device"]?["usage"]?["tx"]?.DeepClone(),
        ["native_udp_attempt"]=_nativeUdpAttempt?.DeepClone(),["quic_available"]=_state is not null && TransportPolicy.QuicAvailable(_state),["quick_ready"]=WarmReady,["preparing"]=Preparing,["verified_at"]=_verified==default?null:_verified.ToUnixTimeSeconds(),["connect_switch_ms"]=_connectMs,["click_to_ready_ms"]=_readyMs,["switch_timings"]=_switchTimings?.DeepClone(),
        ["product_version"]=typeof(VpnRuntime).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion,
        ["uu_candidates"]=_uuInventory?.Candidates,["uu_rejected"]=_uuInventory?.Rejected,
        ["uu_diagnostics"]=new JsonArray((_uuInventory?.Issues ?? []).Select(issue=>(JsonNode?)new JsonObject{["path"]=issue.Path,["code"]=issue.Code,["detail"]=issue.Detail}).ToArray())};
    private static string Code(Exception e)=>e.Message.Length<=80 && e.Message.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')?e.Message:"SERVICE_OPERATION_FAILED";
    internal void BeginStop(){_api.Cancel();_core.Cancel();}
    public void Dispose(){_core.Dispose();_api.Dispose();_gate.Dispose();}
}
