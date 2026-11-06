using System.Diagnostics;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal sealed class UdpDiagnosticRunner : IDisposable
{
    private readonly object _sync=new();
    private readonly CancellationTokenSource _stop=new();
    private readonly AccountApi _api=new();
    private volatile CoreProcess? _core;
    private Task? _task;
    private int _disposed;
    private int _cancelRequested;
    private string _stage="starting";
    private readonly JsonObject _report=new(){["schema"]=1,["phase"]="idle",["trials"]=new JsonArray(),["client_receive_layer"]="connected_udp_socket",["physical_nic_observation"]="not_collected"};
    internal bool Running=>_task is not null && !_task.IsCompleted;
    internal JsonObject Snapshot(){lock(_sync){
        var value=(JsonObject)_report.DeepClone();value["running"]=Running;
        var core=_core;
        if(Running && core is not null && value["current_trial"] is JsonValue node && node.TryGetValue<int>(out int i) && i is >=0 and <6 && value["trials"]?[i] is JsonObject row && row["phase"]?.GetValue<string>()=="running"){
            if(row["client"] is not JsonObject)row["client"]=new JsonObject();
            row["client"]!["counters"]=Counters(core.NativeEvidence,UdpDiagnosticTarget.All[i].Port);
        }
        return value;
    }}
    internal void Start(JsonObject state,DurableState secret)
    {
        if(_task is not null)throw new IOException("DIAGNOSTIC_ALREADY_STARTED");
        var copy=new DurableState{PrivateKey=secret.PrivateKey,PublicKey=secret.PublicKey,Token=secret.Token,
            UuPaths=secret.UuPaths.ToArray(),NativeUdpAdaptive=false,TransportPreference="udp"};
        _task=Task.Run(()=>Run((JsonObject)state.DeepClone(),copy));
    }
    internal void Cancel(){if(Volatile.Read(ref _disposed)!=0)return;Interlocked.Exchange(ref _cancelRequested,1);if(Running)Phase("stopping");_stop.Cancel();_api.Cancel();_core?.Cancel();}
    internal async Task Stop(){Cancel();if(_task is not null)await _task.WaitAsync(TimeSpan.FromSeconds(35));}
    private void Phase(string phase){lock(_sync)_report["phase"]=phase;}
    private void Stage(string stage){_stage=stage;lock(_sync)_report["stage"]=stage;}
    private async Task<JsonObject> Request(string action,string token,JsonObject body)
    {
        Stage("server_"+action);
        return await UdpDiagnosticApi.Call(()=>_api.Call("udp-diagnostics",token,body),_stop.Token);
    }
    private static string Error(Exception error)=>error is OperationCanceledException?"CANCELLED":error.Message switch{
        "DIAGNOSTIC_BUSY" or "DIAGNOSTIC_RATE_LIMITED" or "DIAGNOSTIC_ACCOUNT_NOT_ACTIVE" or "DIAGNOSTIC_EXPIRED_OR_RESTARTED" or "CONTROL_SERVICE_UNAVAILABLE" or "LOGIN_REQUIRED"=>error.Message,
        "DIAGNOSTIC_API_TIMEOUT" or "DIAGNOSTIC_DEADLINE" or "CORE_START_FAILED" or "CORE_READY_TIMEOUT" or "ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED" or "ORACLE_EGRESS_NOT_VERIFIED"=>error.Message,
        _=>"LOCAL_DIAGNOSTIC_FAILED"};
    private static JsonObject Counters(JsonObject ports,int port)
    {
        var result=new JsonObject();
        if(ports[port.ToString()] is JsonObject values)foreach(string key in new[]{"tx_initiations","rx_responses","rx_cookies","rx_invalid","rx_obsolete","read_errors","write_errors","last_read_error","last_write_error","rcvbuf_before","sndbuf_before","rcvbuf_after","sndbuf_after","socket_buffer_error"})
            if(values[key] is JsonValue node){
                if(node.TryGetValue<uint>(out uint value))result[key]=value;
                else if(node.TryGetValue<int>(out int count) && count>=0)result[key]=count;
                else if(node.TryGetValue<long>(out long wide) && wide>=0 && wide<=uint.MaxValue)result[key]=wide;
            }
        return result;
    }
    private static string? Verdict(JsonNode? node)=>node is JsonValue value && value.TryGetValue<string>(out string? text) && text is "PASSED" or "LOCAL_WRITE_ERROR" or "NO_INITIATION_SENT" or "SERVER_OBSERVATION_UNAVAILABLE" or "RETURN_OR_LOCAL_RECEIVE_PATH" or "REPLY_WITHOUT_VERIFIED_EGRESS" or "INSUFFICIENT_OBSERVATION" or "FORWARD_PATH_NOT_OBSERVED" or "SERVER_RESPONSE_NOT_OBSERVED"?text:null;
    private static JsonObject Server(JsonObject source)
    {
        var result=new JsonObject();
        foreach(string key in new[]{"server_started_at","kernel_handshake_at"})if(source[key] is JsonValue node && node.TryGetValue<long>(out long value) && value>=0)result[key]=value;
        foreach(string key in new[]{"kernel_handshake_advanced","index_correlation_available"})if(source[key] is JsonValue node && node.TryGetValue<bool>(out bool value))result[key]=value;
        if(source["capture"] is JsonObject capture){
            var safe=new JsonObject();
            foreach(string key in new[]{"rx_initiations","tx_responses","tx_cookies","ring_evictions","socket_drops"})
                if(capture[key] is JsonValue node && node.TryGetValue<long>(out long value) && value>=0)safe[key]=value;
            if(capture["capture_status"]?.GetValue<string>() is string status && status is "starting" or "observing" or "complete" or "unavailable")safe["capture_status"]=status;
            safe["complete_observation"]=capture["complete_observation"]?.GetValue<bool>()==true;
            result["capture"]=safe;
        }
        if(source["peer_usage_delta"] is JsonObject usage){var safe=new JsonObject();foreach(string key in new[]{"rx","tx"})if(usage[key] is JsonValue node && node.TryGetValue<long>(out long value) && value>=0)safe[key]=value;result["peer_usage_delta"]=safe;}
        return result;
    }
    private async Task Run(JsonObject state,DurableState secret)
    {
        string id=Guid.NewGuid().ToString("D");var started=Stopwatch.StartNew();
        using var cancellation=_stop.Token.Register(()=>{_api.Cancel();_core?.Cancel();});
        _stop.CancelAfter(TimeSpan.FromSeconds(155));
        Phase("starting");
        lock(_sync)_report["ipv6_requested"]=state["tunnel"]?["ipv6_policy"]?.GetValue<string>()=="tunnel";
        lock(_sync){_report["diagnostic_id"]=id;_report["started_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();foreach(var target in UdpDiagnosticTarget.All)_report["trials"]!.AsArray().Add(new JsonObject{["address"]=target.Address,["port"]=target.Port,["phase"]="pending"});}
        try{
            var begin=await Request("start",secret.Token,new JsonObject{["action"]="start",["diagnostic_id"]=id});
            if(begin["diagnostic_id"]?.GetValue<string>()!=id)throw new IOException("INVALID_DIAGNOSTIC_ID");
            Phase("running");
            int index=0;
            foreach(var target in UdpDiagnosticTarget.All){
                _stop.Token.ThrowIfCancellationRequested();
                if(started.Elapsed>TimeSpan.FromSeconds(145))throw new IOException("DIAGNOSTIC_DEADLINE");
                JsonObject row;lock(_sync){row=_report["trials"]![index]!.AsObject();row["phase"]="running";_report["current_trial"]=index;}
                for(int retry=0;;retry++){
                    try{await Request("begin",secret.Token,new JsonObject{["action"]="begin",["diagnostic_id"]=id,["address"]=target.Address,["port"]=target.Port});break;}
                    catch(ApiException pending)when(pending.Message=="DIAGNOSTIC_CAPTURE_STARTING" && retry<8){await Task.Delay(300,_stop.Token);}
                }
                bool verified=false;string error="";var timer=Stopwatch.StartNew();
                _core=new CoreProcess();if(_stop.IsCancellationRequested)_core.Cancel();
                try{
                    Stage("local_core_start");
                    await VpnRuntime.EnsureTunnelRemoved();
                    await _core.Start(state,secret,TunnelTransport.WireGuardUdp,standby:true,diagnosticTarget:target);
                    Stage("egress_probe");await _core.Probe(12);verified=true;
                }catch(Exception failure){error=Error(failure);}
                var evidence=_core.NativeEvidence;
                var indices=evidence[target.Port.ToString()]?["sender_indices"]?.DeepClone() as JsonArray ?? new JsonArray();
                var client=new JsonObject{["counters"]=Counters(evidence,target.Port),["egress_verified"]=verified,["error"]=error,["elapsed_ms"]=(int)Math.Min(180000,timer.ElapsedMilliseconds)};
                Stage("local_core_stop");
                try{await _core.Stop();}finally{_core.Dispose();_core=null;}
                await VpnRuntime.EnsureTunnelRemoved();
                lock(_sync){row["client"]=client.DeepClone();row["phase"]=verified?"passed":"failed";}
                _stop.Token.ThrowIfCancellationRequested();
                var sample=await Request("sample",secret.Token,new JsonObject{["action"]="sample",["diagnostic_id"]=id,["sender_indices"]=indices,["client"]=client,["complete"]=true});
                lock(_sync){row["server"]=Server(sample);row["verdict"]=Verdict(sample["verdict"]);}
                index++;
            }
            Stage("complete");Phase("complete");
        }catch(OperationCanceledException){
            bool requested=Volatile.Read(ref _cancelRequested)!=0;
            Phase(requested?"cancelled":"failed");
            lock(_sync){_report["error"]=requested?"CANCELLED":_stop.IsCancellationRequested?"DIAGNOSTIC_DEADLINE":"LOCAL_DIAGNOSTIC_FAILED";_report["failure_stage"]=_stage;}
        }
        catch(Exception failure){Phase("failed");lock(_sync){_report["error"]=Error(failure);_report["failure_stage"]=_stage;}}
        finally{
            if(_core is not null){try{await _core.Stop();}catch{}finally{_core.Dispose();_core=null;}}
            if(id.Length>0){
                try{
                    // Cancellation interrupts in-flight calls, but finish gets
                    // its own bounded API lifetime so server capture can close.
                    using var finishApi=new AccountApi();
                    var finished=await finishApi.Call("udp-diagnostics",secret.Token,new JsonObject{["action"]="finish",["diagnostic_id"]=id,["cancelled"]=_stop.IsCancellationRequested || Snapshot()["phase"]?.GetValue<string>()!="complete"});
                    if(finished["report"]?["trials"] is JsonArray trials)for(int i=0;i<trials.Count && i<6;i++){
                        if(trials[i]?["server"] is not JsonObject server)continue;
                        lock(_sync){_report["trials"]![i]!["server"]=Server(server);_report["trials"]![i]!["verdict"]=Verdict(trials[i]?["verdict"]);}
                    }
                    lock(_sync)_report["server_capture_closed"]=finished["server_capture_closed"]?.GetValue<bool>()==true;
                }catch{lock(_sync)_report["server_capture_closed"]=false;}
            }
            lock(_sync){_report["finished_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();_report["elapsed_ms"]=(long)Math.Min(300000,started.ElapsedMilliseconds);}
            secret.PrivateKey=secret.Token="";
        }
    }
    public void Dispose(){if(Interlocked.Exchange(ref _disposed,1)!=0)return;Interlocked.Exchange(ref _cancelRequested,1);_stop.Cancel();_core?.Cancel();_api.Dispose();_stop.Dispose();}
}
