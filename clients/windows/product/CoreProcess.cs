using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal sealed class CoreProcess : IDisposable
{
    private volatile Process? _process;
    private readonly CancellationTokenSource _stop=new();
    private IntPtr _job;
    private string _probeSecret="";
    private bool _dualStack;
    private HashSet<string> _expectedIPv4=new(){"152.67.156.100"};
    internal string? VerifiedIPv4 {get;private set;}
    private HttpClient? _probeClient;
    private TaskCompletionSource<VerifiedExit?>? _initialH3,_h3Lifetime;
    private TaskCompletionSource? _parkFence;
    private TaskCompletionSource? _stderrDrained;
    private volatile string? _parkFailure;
    private CancellationTokenSource? _proofCancel;
    private readonly object _proofLock=new();
    private long _proofStarted;
    private volatile bool _parked;
    private ulong _parkedLuid;
    internal bool WasParked=>_parked;
    internal bool Parked=>_parked && Running;
    internal bool StrictParked=>Parked && NativeGuard.TunParked(_parkedLuid);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,long> _startTimings=new();
    internal JsonObject StartTimings=>new(_startTimings.Select(x=>new KeyValuePair<string,JsonNode?>(x.Key,JsonValue.Create(x.Value))));
    private void MarkStart(string key)=>_startTimings[key]=(long)Stopwatch.GetElapsedTime(_proofStarted).TotalMilliseconds;
    internal string ProbeProtocol {get;private set;}="";
    internal bool StandbyCapable{get;private set;}
    internal bool TunActive{get;private set;}
    private string _carrierStage="NOT_STARTED";
    private int _wireGuardReply;
    private readonly NativeUdpEvidence _nativeEvidence=new();
    internal JsonObject NativeEvidence=>_nativeEvidence.Snapshot();
    internal string CarrierStage=>Volatile.Read(ref _carrierStage);
    internal int? NativePort=>CarrierStage=="CARRIER_NATIVE_8443"?8443:CarrierStage=="CARRIER_NATIVE_443"?443:CarrierStage=="CARRIER_NATIVE_51820"?51820:null;
    internal bool HandshakeReplyReceived=>NativePort is not null || Volatile.Read(ref _wireGuardReply)==1;
    private string _safeStage="NOT_STARTED";
    internal string SafeStage=>_parkFailure ?? Volatile.Read(ref _safeStage);
    internal uint Pid=>Running?(uint)_process!.Id:0;
    internal bool Running=>_process is not null && !_process.HasExited;
    internal async Task Start(JsonObject state,DurableState secret,bool standby=false,UdpDiagnosticTarget? diagnosticTarget=null,Action? probeReady=null,Action<int[]>? configuredPorts=null)
    {
        _stop.Token.ThrowIfCancellationRequested();
        bool resume=Parked;
        if(Running && !resume)throw new IOException("CORE_ALREADY_RUNNING");
        if(resume && (!standby || diagnosticTarget is not null || probeReady is null))throw new IOException("CORE_RESUME_REQUIRES_PRIVATE_PROBE");
        if(!resume && _process is not null)await Stop();
        _parkFailure=null;_startTimings.Clear();_proofStarted=Stopwatch.GetTimestamp();
        Platform.VerifyBundle(Platform.Root);
        if(resume && (_parkedLuid!=TunReceipt.VerifyRetained(_process!) || !StrictParked))throw new IOException("TUN_PARK_AUDIT_FAILED");
        MarkStart("bundle_ms");
        _expectedIPv4=EndpointCatalog.Egress(state).ToHashSet();_dualStack=state["tunnel"]?["ipv6_policy"]?.GetValue<string>()=="tunnel";
        _probeSecret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        if(probeReady is not null && !standby)throw new IOException("PROBE_REQUIRES_PRIVATE_STANDBY");
        _proofCancel=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        _initialH3=probeReady is not null && _dualStack?new(TaskCreationOptions.RunContinuationsAsynchronously):null;_h3Lifetime=_initialH3;
        _nativeEvidence.Clear();Volatile.Write(ref _wireGuardReply,0);Volatile.Write(ref _carrierStage,"STARTING");Volatile.Write(ref _safeStage,"LAUNCH");
        StandbyCapable=standby;TunActive=!standby;_parked=false;
        if(!resume)Launch(standby?probeReady is null?"--standby":"--standby-probe":null);
        else _startTimings["adapter_reused"]=1;
        Process owned=_process!;
        var config=CoreConfig.Build(state,secret,_probeSecret,out var nativePorts,diagnosticTarget);
        configuredPorts?.Invoke(nativePorts);
        if(resume)await owned.StandardInput.WriteLineAsync("RESUME");
        await owned.StandardInput.WriteLineAsync(config.ToJsonString());await owned.StandardInput.FlushAsync();
        string? ready;
        async Task<string?> ReadStartup(){
            string? line=await owned.StandardOutput.ReadLineAsync();
            if(probeReady is not null && line=="PROBE_READY"){
                // Start only this generation's private authenticated SOCKS
                // probes while the core creates its unconfigured adapter.
                MarkStart("private_probe_ready_ms");probeReady();
                return await owned.StandardOutput.ReadLineAsync();
            }
            return line;
        }
        try{ready=await ReadStartup().WaitAsync(TimeSpan.FromSeconds(20),_stop.Token);}
        catch(TimeoutException error){throw new IOException("CORE_READY_TIMEOUT",error);}
        if(ready!="READY"){
            try{await owned.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(1));}catch{}
            throw new IOException(SafeStage.StartsWith("CORE_",StringComparison.Ordinal)?SafeStage:"CORE_START_FAILED");
        }
        // Only the cold standby preparation guarantees fresh CreateAdapter;
        // never manufacture ownership from a by-name OpenAdapter fallback.
        MarkStart("adapter_ready_ms");
        if(standby && !resume)TunReceipt.Record(owned);
        MarkStart("receipt_ms");
        Volatile.Write(ref _safeStage,"READY");
    }
    private void Launch(string? argument)
    {
        var info=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Platform.Root,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        if(argument is not null)info.ArgumentList.Add(argument);
        // Fixed configuration/HOLD is supplied only after assignment. An
        // early parent exit closes stdin before the child can create a tunnel.
        _process=Process.Start(info) ?? throw new IOException("CORE_START_FAILED");MarkStart("process_ms");
        _job=CreateJobObject(IntPtr.Zero,null);if(_job==IntPtr.Zero)throw new IOException("JOB_CREATE_FAILED");
        var limits=new JobLimits();limits.Basic.LimitFlags=0x2000; // KILL_ON_JOB_CLOSE
        if(!SetInformationJobObject(_job,9,ref limits,(uint)Marshal.SizeOf<JobLimits>()) || !AssignProcessToJobObject(_job,_process.Handle))throw new IOException("JOB_ASSIGN_FAILED");
        Process owned=_process;_process.EnableRaisingEvents=true;_process.Exited+=(_,_)=>{if(ReferenceEquals(_process,owned)){_h3Lifetime?.TrySetResult(null);_parkFence?.TrySetCanceled();try{NativeGuard.SuspendTun();}catch{}}};
        var drained=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);_stderrDrained=drained;
        _process.ErrorDataReceived+=(_,line)=>{
            if(line.Data is null){drained.TrySetResult();return;}
            if(!ReferenceEquals(_process,owned))return;
            if(line.Data.StartsWith("PARK_AUDIT_FAILED ",StringComparison.Ordinal)){
                string reason=line.Data["PARK_AUDIT_FAILED ".Length..];
                if(reason is "PARK_QUERY_FAILED" or "PARK_CREATOR_MISSING" or "PARK_IP_QUERY_FAILED" or "PARK_IP_NOT_EMPTY" or
                    "PARK_ROUTE_QUERY_FAILED" or "PARK_ROUTE_NOT_EMPTY" or "PARK_DNS_NOT_EMPTY" or "PARK_INTERFACE_QUERY_FAILED" or
                    "PARK_ADMIN_IDENTITY_FAILED" or "PARK_ADMIN_CHANGE_FAILED" or "ORPHAN_IDENTITY_FAILED" or "DORMANT_IP_QUERY_FAILED" or
                    "DORMANT_IP_NOT_EMPTY" or "DORMANT_ROUTE_QUERY_FAILED" or "DORMANT_ROUTE_NOT_EMPTY" or "DORMANT_DNS_QUERY_FAILED" or
                    "DORMANT_DNS_NOT_EMPTY" or "DORMANT_ROUTE_PROTOCOL_NOT_LOCAL" or "DORMANT_ROUTE_NEXT_HOP_UNSAFE" or "DORMANT_ROUTE_DESTINATION_UNSAFE")
                    _parkFailure=reason;
                return;
            }
            if(line.Data=="PARK_FENCE"){_parkFence?.TrySetResult();return;}
            if(_nativeEvidence.Record(line.Data))return;
            if(line.Data=="ADAPTER_EMPTY_AUDITED"){_startTimings["empty_audited"]=1;return;}
            if(line.Data=="ADAPTER_CREATE_BEGIN"){MarkStart("adapter_create_begin_ms");return;}
            if(line.Data=="ADAPTER_PNP_BEGIN" && _startTimings.ContainsKey("adapter_create_begin_ms")){
                // The signed library reports this after DriverInstall and
                // before software device creation. It grants no ownership.
                MarkStart("adapter_pnp_begin_ms");return;
            }
            if(line.Data is string timing && timing.Length<64){
                var pair=timing.Split(' ');
                if(pair.Length==2 && (pair[0] is "ADAPTER_CREATE_MS" or "ADAPTER_AUDIT_MS") && long.TryParse(pair[1],out long ms) && ms is >=0 and <=60000){
                    _startTimings[pair[0]=="ADAPTER_CREATE_MS"?"adapter_create_ms":"adapter_audit_ms"]=ms;return;
                }
            }
            if(line.Data=="EGRESS_H3_UNAVAILABLE"){_h3Lifetime?.TrySetResult(null);return;}
            if(line.Data?.StartsWith("EGRESS_H3_VERIFIED ",StringComparison.Ordinal)==true){
                _h3Lifetime?.TrySetResult(InitialProbeRace.Parse(line.Data,_expectedIPv4,(long)Stopwatch.GetElapsedTime(_proofStarted).TotalMilliseconds));return;
            }
            if(line.Data is "CARRIER_NATIVE_51820" or "CARRIER_NATIVE_443" or "CARRIER_NATIVE_8443")Volatile.Write(ref _carrierStage,line.Data);
            else if(line.Data=="WIREGUARD_REPLY_RECEIVED")Volatile.Write(ref _wireGuardReply,1);
            else if(line.Data is "CARRIER_NATIVE_TRY_51820" or "CARRIER_NATIVE_TRY_443" or "CARRIER_NATIVE_TRY_8443")Volatile.Write(ref _carrierStage,line.Data);
            else if(line.Data is "TUN_CLEANUP_IP_FAILED" or "TUN_CLEANUP_ROUTE_FAILED" or "TUN_CLEANUP_DNS4_FAILED" or "TUN_CLEANUP_DNS6_FAILED")Volatile.Write(ref _safeStage,line.Data);
            else if(line.Data is "CORE_IDENTITY_FAILED" or "CORE_INPUT_FAILED" or "CORE_CONFIGURATION_FAILED" or "CORE_CREATE_FAILED" or "CORE_START_FAILED" or "CORE_CLOSE_FAILED"){
                if(line.Data!="CORE_CLOSE_FAILED" || !SafeStage.StartsWith("TUN_CLEANUP_",StringComparison.Ordinal))Volatile.Write(ref _safeStage,line.Data);
            }
        };_process.BeginErrorReadLine();
    }
    private void EndPeer()
    {
        lock(_proofLock){
            _proofCancel?.Cancel();_proofCancel?.Dispose();_proofCancel=null;
            _h3Lifetime?.TrySetResult(null);_h3Lifetime=null;_initialH3=null;
            _probeClient?.Dispose();_probeClient=null;_probeSecret="";
            VerifiedIPv4=null;ProbeProtocol="";
        }
    }
    internal async Task PrepareHolder(CancellationToken cancel=default)
    {
        if(Parked)return;
        if(Running)throw new IOException("CORE_ALREADY_RUNNING");
        if(_process is not null)await Stop();
        Platform.VerifyBundle(Platform.Root);
        _parkFailure=null;_startTimings.Clear();_proofStarted=Stopwatch.GetTimestamp();
        _parkFence=new(TaskCreationOptions.RunContinuationsAsynchronously);
        StandbyCapable=true;TunActive=false;
        Launch("--adapter-holder");
        await _process!.StandardInput.WriteLineAsync("HOLD");await _process.StandardInput.FlushAsync();
        await AcceptPark(_process,cancel);
        TunReceipt.Record(_process);
        _parkedLuid=TunReceipt.VerifyRetained(_process);
        if(!NativeGuard.TunParked(_parkedLuid))throw new IOException("TUN_PARK_AUDIT_FAILED");
        _parked=true;
    }
    private async Task AcceptPark(Process owner,CancellationToken cancel)
    {
        var fence=_parkFence ?? throw new IOException("CORE_PARK_FENCE_MISSING");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token,cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        if(await owner.StandardOutput.ReadLineAsync(deadline.Token)!="PARKED"){
            // A failing child's stderr and stdout close independently. Read
            // the fixed audit reason even when its stdout EOF arrived first.
            if(_stderrDrained is not null)await Task.WhenAny(_stderrDrained.Task,Task.Delay(1000,deadline.Token));
            throw new IOException(_parkFailure ?? "CORE_PARK_FAILED");
        }
        // stderr is an independent ordered stream. Drain its prior generation
        // before publishing Off or arming another H3/handshake observer.
        await fence.Task.WaitAsync(deadline.Token);_parkFence=null;
        _nativeEvidence.Clear();_startTimings.Clear();Volatile.Write(ref _wireGuardReply,0);
        Volatile.Write(ref _carrierStage,"NOT_STARTED");Volatile.Write(ref _safeStage,"ADAPTER_PARKED");
        TunActive=false;
    }
    internal async Task Park()
    {
        if(Parked)return;
        if(!StandbyCapable || !Running)throw new IOException("CORE_NOT_READY");
        NativeGuard.SuspendTun();EndPeer();_parkFailure=null;
        _parkFence=new(TaskCreationOptions.RunContinuationsAsynchronously);
        Process owner=_process!;
        await owner.StandardInput.WriteLineAsync("PARK");await owner.StandardInput.FlushAsync();
        await AcceptPark(owner,_stop.Token);
        _parkedLuid=TunReceipt.VerifyRetained(owner);
        if(!NativeGuard.TunParked(_parkedLuid))throw new IOException("TUN_PARK_AUDIT_FAILED");
        _parked=true;
    }
    private async Task CoreCommand(string command,string expected)
    {
        if(!Running || !StandbyCapable)throw new IOException("CORE_NOT_READY");
        await _process!.StandardInput.WriteLineAsync(command);await _process.StandardInput.FlushAsync();
        if(await _process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5),_stop.Token)!=expected)throw new IOException("CORE_TRANSITION_FAILED");
    }
    internal async Task Activate(){await CoreCommand("ACTIVATE","TUN_ACTIVE");TunActive=true;}
    internal async Task Deactivate(){NativeGuard.SuspendTun();await CoreCommand("DEACTIVATE","STANDBY_READY");TunActive=false;}
    internal async Task<long> Probe(int timeoutSeconds=12)
    {
        var lifetime=_proofCancel ?? throw new IOException("CORE_NOT_RUNNING");
        if(!Running || Parked)throw new IOException("CORE_NOT_RUNNING");
        var cancellation=lifetime.Token;
        if(_probeClient is null){
            var proxy=new WebProxy("socks5://127.0.0.1:28083"){Credentials=new NetworkCredential("service",_probeSecret)};
            _probeClient=new HttpClient(new SocketsHttpHandler{Proxy=proxy,UseProxy=true,UseCookies=false,AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
        }
        var client=_probeClient;
        var initial=Interlocked.Exchange(ref _initialH3,null);
        async Task<VerifiedExit> Tcp(CancellationToken token){
            string address="";
            var timer=Stopwatch.StartNew();
            var ipv4=EgressProbe.Verify(client,timeoutSeconds,()=>HandshakeReplyReceived,token,_dualStack?"https://1.1.1.1/cdn-cgi/trace":"https://www.cloudflare.com/cdn-cgi/trace",allowed:_expectedIPv4,observed:ip=>address=ip);
            if(!_dualStack)await ipv4;
            else{
                var ipv6=EgressProbe.Verify(client,timeoutSeconds,()=>HandshakeReplyReceived,token,"https://[2606:4700:4700::1111]/cdn-cgi/trace","2603:c020:c015:8100::10");
                await Task.WhenAll(ipv4,ipv6);
            }
            return new VerifiedExit(address,timer.ElapsedMilliseconds,"https");
        }
        try{
            var proof=await InitialProbeRace.Verify(initial?.Task,Tcp,cancellation);
            lock(_proofLock){
                if(!ReferenceEquals(lifetime,_proofCancel))throw new OperationCanceledException(cancellation);
                VerifiedIPv4=proof.Address;ProbeProtocol=proof.Protocol;return proof.ElapsedMs;
            }
        }
        catch(IOException error)when(error.Message=="ORACLE_PROBE_TIMEOUT"){
            if(ReferenceEquals(Interlocked.CompareExchange(ref _probeClient,null,client),client))client.Dispose();
            throw;
        }
    }
    internal async Task Stop()
    {
        EndPeer();_parked=false;_parkedLuid=0;_parkFence=null;
        _nativeEvidence.Clear();Volatile.Write(ref _wireGuardReply,0);Volatile.Write(ref _carrierStage,"NOT_STARTED");
        if(_process is null)return;
        NativeGuard.SuspendTun();
        if(!_process.HasExited){
            _process.StandardInput.Close();
            try{await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
            catch{_process.Kill(true);await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));}
        }
        _process.Dispose();_process=null;StandbyCapable=false;TunActive=false;
        _nativeEvidence.Clear();Volatile.Write(ref _wireGuardReply,0);Volatile.Write(ref _carrierStage,"NOT_STARTED");
        if(_job!=IntPtr.Zero){CloseHandle(_job);_job=IntPtr.Zero;}
        _probeSecret="";
    }
    internal void Cancel()=>_stop.Cancel();
    public void Dispose(){_stop.Cancel();try{Stop().GetAwaiter().GetResult();}catch{}if(_job!=IntPtr.Zero){CloseHandle(_job);_job=IntPtr.Zero;}_stop.Dispose();}
    [StructLayout(LayoutKind.Sequential)]private struct BasicLimits{public long ProcessTime,JobTime;public uint LimitFlags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
    [StructLayout(LayoutKind.Sequential)]private struct IoCounters{public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)]private struct JobLimits{public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]private static extern IntPtr CreateJobObject(IntPtr security,string? name);
    [DllImport("kernel32.dll")]private static extern bool SetInformationJobObject(IntPtr job,int kind,ref JobLimits data,uint length);
    [DllImport("kernel32.dll")]private static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")]private static extern bool CloseHandle(IntPtr handle);
}
