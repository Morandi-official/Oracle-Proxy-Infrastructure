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
    private bool _initialCarrierSelected;
    private readonly JsonObject _carrierFailures=new();
    private TunnelTransport Preferred(){
        if(_secret.TransportPreference!="auto")return TransportPolicy.First(_secret.TransportPreference,_state);
        if(_secret.CarrierHintUntil>DateTimeOffset.UtcNow.ToUnixTimeSeconds() && _secret.CarrierNetworkHash==CarrierMemory.NetworkHash(_state)){
            if(_secret.CarrierHint=="wireguard-quic" && _state is not null && TransportPolicy.QuicAvailable(_state))return TunnelTransport.WireGuardQuic;
            if(_secret.CarrierHint=="wireguard-https" && _state?["tunnel"]?["https_relay"]?.GetValue<bool>()==true)return TunnelTransport.WireGuardHttps;
        }
        return _state is null?TunnelTransport.WireGuardUdp:_carriers.Preferred(_state);
    }
    private void RememberVerifiedCarrier(){
        string name=TransportPolicy.Name(_transport),network=CarrierMemory.NetworkHash(_state);
        int port=_transport==TunnelTransport.WireGuardUdp?_core.NativePort??0:0;
        if(_secret.CarrierHint!=name || _secret.NativeUdpPortHint!=port || _secret.CarrierNetworkHash!=network || _secret.CarrierHintUntil<DateTimeOffset.UtcNow.ToUnixTimeSeconds()+60){
            _secret.CarrierHint=name;_secret.NativeUdpPortHint=port;_secret.CarrierNetworkHash=network;_secret.CarrierHintUntil=DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();_secret.Save();
        }
    }
    private JsonObject? _nativeUdpAttempt;
    private void RecordNativeProbe(bool verified)
    {
        if(_transport!=TunnelTransport.WireGuardUdp || _nativeUdpAttempt is null)return;
        _nativeUdpAttempt["selected_port"]=_core.NativePort;
        _nativeUdpAttempt["ports"]=_core.NativeEvidence;
        _nativeUdpAttempt["server_handshake_at_observed"]=_state?["device"]?["handshake_at"]?.DeepClone();
        _nativeUdpAttempt["probe_result"]=verified?"oracle_egress_verified":CodeForNativeProbe();
        if(!verified)_nativeUdpAttempt["probe_failures"]=_nativeUdpAttempt["probe_failures"]!.GetValue<int>()+1;
        else{_nativeUdpAttempt["probe_failures"]=0;if(_nativeUdpAttempt["verified_after_start_ms"] is null)_nativeUdpAttempt["verified_after_start_ms"]=(long)System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted).TotalMilliseconds;}
        _nativeUdpAttempt["core_age_ms"]=System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted).Ticks/TimeSpan.TicksPerMillisecond;
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
    private bool Preparing=>!_secret.ConnectIntent && DeviceRegistration.Confirmed(_state) && _secret.Token.Length>0 && DateTimeOffset.UtcNow<_prepareUntil;
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
        _carriers.Observe(CarrierMemory.Scope(_state));
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
                        if(_carriers.Observe(CarrierMemory.Scope(_state))){
                            _nativeUdpAttempt=null;_secret.CarrierHintUntil=0;await StopCore();_transport=TransportPolicy.First(_secret.TransportPreference,_state);_probeFailures=0;
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
                                _latency=await pending;RememberVerifiedCarrier();RecordNativeProbe(true);_verified=DateTimeOffset.UtcNow;_verifiedGeneration=_generation;_failure=null;_probeFailures=0;_error="";
                                if(_secret.ConnectIntent && NativeGuard.TunPermitted)MarkConnected();
                            }catch(Exception error){
                                _verified=default;_stage="ORACLE_EGRESS_PROBE";Failed(error);RecordNativeProbe(false);
                                if(_secret.ConnectIntent){_mode="protected";_latency=null;}
                                if(_error is not ("ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED"))await StopCore();
                            }
                        }else{try{await pending;}catch{}}
                    }
                    if(_secret.Token.Length>0 && _refreshPending is null && DateTimeOffset.UtcNow>=_nextRefresh){
                        _refreshToken=_secret.Token;_refreshPending=_api.Call("presence",_refreshToken,new JsonObject{["mode"]=DeviceRegistration.ReportMode(_mode,DeviceRegistration.Confirmed(_state),_secret.RecoveryRequired),["transport"]=_mode=="connected" && _secret.ConnectIntent && NativeGuard.TunPermitted?TransportPolicy.Name(_transport):null});_nextRefresh=DateTimeOffset.UtcNow.AddSeconds(5);
                    }
                    if((_secret.ConnectIntent && !_secret.RecoveryRequired) || Preparing){
                        if(!ActivePolicy()){
                            await StopCore();_latency=null;
                            if(_secret.ConnectIntent)_mode="protected";
                        }else{
                            if(!_initialCarrierSelected){_transport=Preferred();_initialCarrierSelected=true;}
                            if(_probePending is null && _probeFailures>=2 && System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted)>=TimeSpan.FromSeconds(_transport==TunnelTransport.WireGuardUdp?8:6) && TransportPolicy.Next(_transport,_state!) is TunnelTransport next){
                                if(_transport==TunnelTransport.WireGuardUdp && _nativeUdpAttempt is not null)_nativeUdpAttempt["ports"]=_core.NativeEvidence;
                                _carrierFailures[TransportPolicy.Name(_transport)]=new JsonObject{["error"]=_error,["carrier_stage"]=_core.CarrierStage,["probe_failures"]=_probeFailures,["core_uptime_ms"]=(long)System.Diagnostics.Stopwatch.GetElapsedTime(_carrierStarted).TotalMilliseconds,["failed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["core_pid"]=_core.Pid};
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
                    }else if(!_secret.ConnectIntent && _core.Running){await StopCore();_transport=Preferred();_probeFailures=0;}
                }catch(Exception error){
                    Failed(error);
                    if(_secret.ConnectIntent){if(!NativeGuard.Active)await StopCore();_mode=_secret.RecoveryRequired?"recovery":"protected";_latency=null;}
                }
            }finally{_gate.Release();}
            await Task.Delay(200,cancel);
        }
    }
    private async Task StopCore(){
        _generation++;
        var pending=_probePending;_probePending=null;
        if(pending is not null)_=pending.ContinueWith(t=>{_ = t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        await _core.Stop();_verified=default;_runningProfile="";_nextProbe=default;
    }
    private void AdoptNativePort(){
        if(_secret.NativeUdpPortPreference==0 && (_secret.TransportPreference is "auto" or "udp") && TransportPolicy.Native8443Available(_state)){_secret.NativeUdpPortPreference=8443;_secret.Save();}
    }
    private async Task Refresh(){_stage="ACCOUNT_STATE";_state=await _api.Call("state",_secret.Token);_received=DateTimeOffset.UtcNow;_error="";}
    private bool ActivePolicy()=>DeviceRegistration.Confirmed(_state) && _state?["account"]?["status"]?.GetValue<string>()=="active" && _state["observed_at"]?.GetValue<long>() is long at && Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-at)<=20;
    private async Task StartCore(bool standby=false,bool guardInstalled=false)
    {
        if(!ActivePolicy())throw new IOException("ACCOUNT_NOT_ACTIVE");
        if(_secret.UuPaths.Any(path=>!UuDiscovery.Trusted(path)))throw new IOException("UU_TRUST_CHANGED_REFRESH_REQUIRED");
        _stage="TUN_CLEANUP";await EnsureTunnelRemoved();
        if(!standby){_stage="GUARD_INSTALL";if(!guardInstalled)NativeGuard.Apply(_secret.UuPaths);_mode="protected";}
        try{
            _stage="CORE_START";_probeFailures=0;_generation++;_verified=default;_verifiedGeneration=-1;_latency=null;_carrierStarted=System.Diagnostics.Stopwatch.GetTimestamp();
            if(_transport==TunnelTransport.WireGuardUdp)_nativeUdpAttempt=new JsonObject{
                ["endpoint_port"]=int.Parse(_state!["tunnel"]!["endpoint"]!.GetValue<string>().Split(':')[1]),
                ["started_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["started_without_tun"]=standby,
                ["inner_mtu"]=_state!["tunnel"]?["ipv6_policy"]?.GetValue<string>()=="tunnel"?1280:1200,["preferred_port"]=_secret.NativeUdpPortPreference,["socket_binding"]=_secret.NativeUdpPortPreference==8443?"native_udp_fixed_8443":"native_udp_dual_port",["probe_result"]="pending",["probe_failures"]=0,["core_age_ms"]=0};
            await _core.Start(_state!,_secret,_transport,standby:true);
            if(!standby){_stage="TUN_ACTIVATE";await _core.Activate();_stage="TUN_AUTHORIZE";NativeGuard.AuthorizeTun(_core.Pid);}
            _runningProfile=Profile();_nextProbe=default;
        }catch{await StopCore();if(!standby)_mode="protected";throw;}
    }
    internal async Task<JsonObject> Command(JsonObject value)
    {
        if(!value.TryGetPropertyValue("version",out var version)||version?.GetValue<int>()!=1)throw new IOException("INVALID_PROTOCOL");
        string command=value["command"]?.GetValue<string>() ?? "";
        var fields=command=="Login"?new[]{"version","command","username","password"}:command=="ConfirmDevice"?new[]{"version","command","device_name","confirm"}:new[]{"version","command"};
        if(value.Count!=fields.Length || fields.Any(field=>!value.ContainsKey(field)))throw new IOException("INVALID_FIELDS");
        if(command is not ("Status" or "Login" or "ConfirmDevice" or "Connect" or "Disconnect" or "Quit" or "Logout" or "RefreshUu" or "Prepare" or "PreferAuto" or "PreferUdp" or "PreferUdp8443" or "PreferAuto8443" or "PreferQuic"))throw new IOException("UNKNOWN_COMMAND");
        await _gate.WaitAsync();
        try{
            switch(command){
            case "Prepare":_prepareUntil=DateTimeOffset.UtcNow.AddMinutes(5);break;
            case "PreferAuto":case "PreferUdp":case "PreferUdp8443":case "PreferAuto8443":case "PreferQuic":
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_TRANSPORT_CHANGE");
                if((command is "PreferUdp8443" or "PreferAuto8443") && !TransportPolicy.Native8443Available(_state))throw new IOException("NATIVE_UDP8443_NOT_AVAILABLE");
                if(command=="PreferQuic" && (_state is null || !TransportPolicy.QuicAvailable(_state)))throw new IOException("QUIC_NOT_AVAILABLE");
                await StopCore();_carriers.Clear();_carrierFailures.Clear();_nativeUdpAttempt=null;_probeFailures=0;
                _secret.TransportPreference=command is "PreferUdp" or "PreferUdp8443"?"udp":command=="PreferQuic"?"quic":"auto";
                _secret.NativeUdpPortPreference=command is "PreferUdp8443" or "PreferAuto8443"?8443:0;
                _secret.CarrierHintUntil=0;_secret.Save();_transport=Preferred();_initialCarrierSelected=true;
                _prepareUntil=default;_error="";_failure=null;_connectMs=null;_switchTimings=null;_clickStarted=0;_readyMs=null;break;
            case "Login":
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_LOGIN");
                await StopCore();_transport=TransportPolicy.First(_secret.TransportPreference,_state);_initialCarrierSelected=false;_probeFailures=0;_nativeUdpAttempt=null;
                _stage="ACCOUNT_LOGIN";string username=value["username"]!.GetValue<string>(),password=value["password"]!.GetValue<string>();
                if(username.Length is <3 or >64 || password.Length is <1 or >128)throw new IOException("INVALID_CREDENTIALS");
                if(_secret.PrivateKey.Length==0){
                    byte[] key=RandomNumberGenerator.GetBytes(32),pub=new byte[32];key[0]&=248;key[31]&=127;key[31]|=64;
                    try{X25519.GeneratePublicKey(key,0,pub,0);_secret.PrivateKey=Convert.ToBase64String(key);_secret.PublicKey=Convert.ToBase64String(pub);_secret.Save();}
                    finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(pub);}
                }
                var login=await _api.Call("authenticate","",new JsonObject{["username"]=username,["password"]=password,["public_key"]=_secret.PublicKey,["device_name"]=Environment.MachineName,["client_version"]=DeviceRegistration.Version});
                _secret.Token=login["token"]!.GetValue<string>();login.Remove("token");_secret.Save();_state=login;_received=DateTimeOffset.UtcNow;_error="";AdoptNativePort();break;
            case "ConfirmDevice":{
                if(_secret.ConnectIntent)throw new IOException("DISCONNECT_BEFORE_ENROLLMENT");
                if(_secret.Token.Length==0)throw new IOException("LOGIN_REQUIRED");
                if(_secret.RecoveryRequired)throw new IOException("RECOVERY_REQUIRED");
                if(value["confirm"] is not JsonValue confirmation || !confirmation.TryGetValue<bool>(out bool confirmed) || !confirmed)throw new IOException("DEVICE_CONFIRMATION_REQUIRED");
                string name=value["device_name"]?.GetValue<string>()?.Trim() ?? "";
                if(name.Length is <1 or >80 || name.Any(char.IsControl))throw new IOException("INVALID_NAME");
                _stage="DEVICE_CONFIRMATION";
                var registered=await _api.Call("enroll",_secret.Token,new JsonObject{["device_name"]=name,["confirm"]=true});
                if(!DeviceRegistration.Confirmed(registered))throw new IOException("DEVICE_CONFIRMATION_REQUIRED");
                _state=registered;_received=DateTimeOffset.UtcNow;_error="";_failure=null;_mode="disconnected";AdoptNativePort();_prepareUntil=DateTimeOffset.UtcNow.AddMinutes(5);
                break;
            }
            case "Connect":{
                var timer=System.Diagnostics.Stopwatch.StartNew();_connectMs=null;_switchTimings=new JsonObject();
                if(_secret.Token.Length==0)throw new IOException("LOGIN_REQUIRED");
                if(!DeviceRegistration.Confirmed(_state))throw new IOException("DEVICE_CONFIRMATION_REQUIRED");
                if(_secret.RecoveryRequired)throw new IOException("RECOVERY_REQUIRED");
                if(_core.Running && _mode=="connected" && _secret.ConnectIntent)break;
                if(_secret.ConnectIntent && _core.Running && NativeGuard.TunPermitted){_nextProbe=default;break;}
                _clickStarted=System.Diagnostics.Stopwatch.GetTimestamp();_readyMs=null;
                // A new explicit-protocol connection must try that protocol,
                // even when a previous fallback is still warm. Auto alone may
                // reuse the learned fallback without another primary timeout.
                if(!_secret.ConnectIntent && _secret.TransportPreference!="auto" && _transport!=TransportPolicy.First(_secret.TransportPreference,_state)){
                    await StopCore();_transport=Preferred();_probeFailures=0;_carrierFailures.Clear();_nativeUdpAttempt=null;
                }
                bool warm=WarmReady;
                bool reusable=_core.Running && !_core.TunActive && ActivePolicy() && _runningProfile==Profile();
                if(!_secret.ConnectIntent && !reusable){await StopCore();_transport=Preferred();_probeFailures=0;}
                using var uuMaintenance=UuAclRepair.AcquireMaintenance();
                if(_carriers.Observe(CarrierMemory.Scope(_state))){await StopCore();_transport=TransportPolicy.First(_secret.TransportPreference,_state);_probeFailures=0;warm=false;reusable=false;}
                _stage="UU_DISCOVERY";var inventory=UuDiscovery.Discover();_uuInventory=inventory;_switchTimings["uu_discovery_ms"]=timer.ElapsedMilliseconds;
                if(inventory.Candidates>0 && inventory.Paths.Length==0)throw new IOException("UU_TRUST_NOT_VERIFIED");
                // Process exceptions are part of the prepared configuration.
                if(reusable && !_secret.UuPaths.SequenceEqual(inventory.Paths,StringComparer.OrdinalIgnoreCase)){await StopCore();warm=false;reusable=false;_transport=Preferred();}
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
            case "Quit":await Disconnect(keepPrepared:false);break;
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
    private async Task Disconnect(bool keepPrepared=true)
    {
        try{
            _stage="DISCONNECT";
            bool keep=keepPrepared && _core.Running && _core.StandbyCapable && ActivePolicy() && _runningProfile==Profile();
            _stage="DISCONNECT_DEACTIVATE";
            if(keep){if(_core.TunActive)await _core.Deactivate();}
            else await StopCore();
            _stage="DISCONNECT_AUDIT";
            keep=await AuditDisconnectedTunnel(keep,StopCore);
            _stage="DISCONNECT_STATE";
            _secret.ConnectIntent=false;_secret.RecoveryRequired=false;_secret.Save();
            _stage="DISCONNECT_GUARD_CLEAR";
            NativeGuard.Clear();_mode="disconnected";_error="";_latency=null;_failure=null;_stage="IDLE";_probeFailures=0;
            _prepareUntil=keepPrepared?DateTimeOffset.UtcNow.AddMinutes(5):default;
            if(!keep)_transport=Preferred();
        }catch(Exception error){
            _secret.ConnectIntent=true;_secret.RecoveryRequired=true;_secret.Save();
            try{NativeGuard.Apply(_secret.UuPaths.Where(UuDiscovery.Trusted).ToArray());}catch{}
            _mode="recovery";throw new IOException("RECOVERY_REQUIRED",error);
        }
    }
    // A dormant core is a reconnect optimization, not a prerequisite for Off.
    // If its adapter fails the full inactivity audit, close our core and require
    // complete adapter removal before committing Off or clearing any guard.
    internal static async Task<bool> AuditDisconnectedTunnel(bool keep,Func<Task> stopCore)
    {
        if(keep){
            try{await EnsureTunnelInactive();return true;}
            catch(IOException error)when(error.Message=="OWNED_TUNNEL_CLEANUP_NOT_VERIFIED"){
                await stopCore();
            }
        }
        await EnsureTunnelRemoved();return false;
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
    // GetAllNetworkInterfaces can also retain an OS NotPresent description
    // after the device has been removed. Every other state remains present,
    // including disabled, dormant, testing, and unknown interfaces.
    internal static bool PresentTunnel(string name,OperationalStatus status)=>name=="OracleProxy" && status!=OperationalStatus.NotPresent;
    internal static async Task EnsureTunnelRemoved()
    {
        for(int i=0;i<30;i++){
            if(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>PresentTunnel(n.Name,n.OperationalStatus)))return;
            await Task.Delay(100);
        }
        throw new IOException("OWNED_TUNNEL_REMOVAL_NOT_VERIFIED");
    }
    internal static bool TunnelInactive()=>!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy" &&
        (n.OperationalStatus==OperationalStatus.Up || n.GetIPProperties().UnicastAddresses.Any(a=>!a.Address.IsIPv6LinkLocal)));
    private JsonObject Snapshot(bool ok=true)
    {
        // Local TUN interface octets, not the delayed server billing totals.
        // Missing/stopped interfaces produce no sample rather than a false zero.
        JsonObject? traffic=null;
        if(_secret.ConnectIntent && _core.Running && NativeGuard.TunPermitted){
            try{
                var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.Name=="OracleProxy" && n.OperationalStatus==OperationalStatus.Up);
                if(nic is not null){var stats=nic.GetIPv4Statistics();traffic=new(){["sample_ms"]=Environment.TickCount64,["rx_bytes"]=stats.BytesReceived,["tx_bytes"]=stats.BytesSent};}
            }catch(NetworkInformationException){}catch(System.Net.Sockets.SocketException){}
        }
        return new(){["registration"]=_state?["registration"]?.DeepClone(),["devices"]=_state?["devices"]?.DeepClone(),["device_registered"]=DeviceRegistration.Confirmed(_state),["traffic"]=traffic,["verified_exit_ip"]=_mode=="connected" && _verifiedGeneration==_generation && NativeGuard.TunPermitted?"152.67.156.100":null,["ok"]=ok,["schema"]=1,["mode"]=_secret.RecoveryRequired || (_secret.ConnectIntent && !NativeGuard.Active)?"recovery":_mode=="connected" && !NativeGuard.TunPermitted?"protected":_mode,["error"]=_error,["intent"]=_secret.ConnectIntent,["guard"]=_secret.ConnectIntent?NativeGuard.Active:false,["latency_ms"]=_latency,["received_at"]=_received==default?null:_received.ToUnixTimeSeconds(),["observed_at"]=_state?["observed_at"]?.DeepClone(),["account"]=_state?["account"]?.DeepClone(),["period"]=_state?["period"]?.DeepClone(),["uu_verified_programs"]=_secret.UuPaths.Length,
        ["ipv6_policy"]=_state?["tunnel"]?["ipv6_policy"]?.DeepClone(),["verified_exit_ipv6"]=_mode=="connected" && _verifiedGeneration==_generation && NativeGuard.TunPermitted && _state?["tunnel"]?["ipv6_policy"]?.GetValue<string>()=="tunnel"?"2603:c020:c015:8100::10":null,
        ["transport_preference"]=_secret.TransportPreference,["transport_address"]=_transport==TunnelTransport.WireGuardHttps?"152.67.156.100":TransportPolicy.IngressAddress(_state),["native_udp_port_preference"]=_secret.NativeUdpPortPreference,["native_udp_8443_available"]=TransportPolicy.Native8443Available(_state),["carrier_stage"]=_core.CarrierStage,["carrier_failures"]=_carrierFailures.DeepClone(),["failure"]=_failure?.DeepClone(),["connection_stage"]=_stage,["core_stage"]=_core.SafeStage,["core_pid"]=_core.Pid,["tun_permitted"]=_secret.ConnectIntent && NativeGuard.TunPermitted,["transport"]=TransportPolicy.Name(_transport),
        ["server_handshake_at"]=_state?["device"]?["handshake_at"]?.DeepClone(),["peer_rx_bytes"]=_state?["device"]?["usage"]?["rx"]?.DeepClone(),["peer_tx_bytes"]=_state?["device"]?["usage"]?["tx"]?.DeepClone(),
        ["native_udp_attempt"]=_nativeUdpAttempt?.DeepClone(),["native_udp_selected_port"]=_core.NativePort,["client_handshake_reply"]=_core.HandshakeReplyReceived,["quic_available"]=_state is not null && TransportPolicy.QuicAvailable(_state),["quick_ready"]=WarmReady,["preparing"]=Preparing,["verified_at"]=_verified==default?null:_verified.ToUnixTimeSeconds(),["connect_switch_ms"]=_connectMs,["click_to_ready_ms"]=_readyMs,["switch_timings"]=_switchTimings?.DeepClone(),
        ["product_version"]=typeof(VpnRuntime).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion,
        ["uu_candidates"]=_uuInventory?.Candidates,["uu_rejected"]=_uuInventory?.Rejected,
        ["uu_diagnostics"]=new JsonArray((_uuInventory?.Issues ?? []).Select(issue=>(JsonNode?)new JsonObject{["path"]=issue.Path,["code"]=issue.Code,["detail"]=issue.Detail}).ToArray())};
    }
    private static string Code(Exception e)=>e.Message.Length<=80 && e.Message.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')?e.Message:"SERVICE_OPERATION_FAILED";
    internal void BeginStop(){_api.Cancel();_core.Cancel();}
    public void Dispose(){_core.Dispose();_api.Dispose();_gate.Dispose();}
}
