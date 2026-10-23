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
    private HttpClient? _probeClient;
    internal bool StandbyCapable{get;private set;}
    internal bool TunActive{get;private set;}
    private string _carrierStage="NOT_STARTED";
    private int _wireGuardReply;
    internal string CarrierStage=>Volatile.Read(ref _carrierStage);
    internal int? NativePort=>CarrierStage=="CARRIER_NATIVE_443"?443:CarrierStage=="CARRIER_NATIVE_51820"?51820:null;
    internal bool HandshakeReplyReceived=>NativePort is not null || Volatile.Read(ref _wireGuardReply)==1;
    private string _safeStage="NOT_STARTED";
    internal string SafeStage=>Volatile.Read(ref _safeStage);
    internal uint Pid=>Running?(uint)_process!.Id:0;
    internal bool Running=>_process is not null && !_process.HasExited;
    internal async Task Start(JsonObject state,DurableState secret,TunnelTransport transport=TunnelTransport.WireGuardUdp,bool standby=false)
    {
        _stop.Token.ThrowIfCancellationRequested();
        if(Running)throw new IOException("CORE_ALREADY_RUNNING");
        if(_process is not null)await Stop();
        Volatile.Write(ref _wireGuardReply,0);Volatile.Write(ref _carrierStage,"STARTING");Volatile.Write(ref _safeStage,"LAUNCH");Platform.VerifyBundle(Platform.Root);_probeSecret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var info=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Platform.Root,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        if(standby)info.ArgumentList.Add("--standby");
        StandbyCapable=standby;TunActive=!standby;
        // A suspended native launch + job assignment would narrow the creation
        // race further. Persistent WFP already blocks direct user traffic.
        _process=Process.Start(info) ?? throw new IOException("CORE_START_FAILED");
        _job=CreateJobObject(IntPtr.Zero,null);if(_job==IntPtr.Zero)throw new IOException("JOB_CREATE_FAILED");
        var limits=new JobLimits();limits.Basic.LimitFlags=0x2000; // KILL_ON_JOB_CLOSE
        if(!SetInformationJobObject(_job,9,ref limits,(uint)Marshal.SizeOf<JobLimits>()) || !AssignProcessToJobObject(_job,_process.Handle))throw new IOException("JOB_ASSIGN_FAILED");
        Process owned=_process;_process.EnableRaisingEvents=true;_process.Exited+=(_,_)=>{if(ReferenceEquals(_process,owned)){try{NativeGuard.SuspendTun();}catch{}}};
        _process.ErrorDataReceived+=(_,line)=>{
            if(line.Data is "CARRIER_H3_TLS" or "CARRIER_H3_SETTINGS" or "CARRIER_H3_AUTH" or "CARRIER_H3_READY" or "CARRIER_NATIVE_51820" or "CARRIER_NATIVE_443")Volatile.Write(ref _carrierStage,line.Data);
            else if(line.Data=="WIREGUARD_REPLY_RECEIVED")Volatile.Write(ref _wireGuardReply,1);
            else if(line.Data is "CARRIER_NATIVE_TRY_51820" or "CARRIER_NATIVE_TRY_443")Volatile.Write(ref _carrierStage,line.Data);
            else if(line.Data is "TUN_CLEANUP_IP_FAILED" or "TUN_CLEANUP_ROUTE_FAILED" or "TUN_CLEANUP_DNS4_FAILED" or "TUN_CLEANUP_DNS6_FAILED")Volatile.Write(ref _safeStage,line.Data);
            else if(line.Data is "CORE_IDENTITY_FAILED" or "CORE_INPUT_FAILED" or "CORE_CONFIGURATION_FAILED" or "CORE_CREATE_FAILED" or "CORE_START_FAILED" or "CORE_CLOSE_FAILED"){
                if(line.Data!="CORE_CLOSE_FAILED" || !SafeStage.StartsWith("TUN_CLEANUP_",StringComparison.Ordinal))Volatile.Write(ref _safeStage,line.Data);
            }
        };_process.BeginErrorReadLine();
        await _process.StandardInput.WriteLineAsync(CoreConfig.Build(state,secret,_probeSecret,transport).ToJsonString());await _process.StandardInput.FlushAsync();
        string? ready;
        try{ready=await _process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20),_stop.Token);}
        catch(TimeoutException error){throw new IOException("CORE_READY_TIMEOUT",error);}
        if(ready!="READY"){
            try{await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(1));}catch{}
            throw new IOException(SafeStage.StartsWith("CORE_",StringComparison.Ordinal)?SafeStage:"CORE_START_FAILED");
        }
        Volatile.Write(ref _safeStage,"READY");
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
        if(!Running)throw new IOException("CORE_NOT_RUNNING");
        if(_probeClient is null){
            var proxy=new WebProxy("socks5://127.0.0.1:28083"){Credentials=new NetworkCredential("service",_probeSecret)};
            _probeClient=new HttpClient(new SocketsHttpHandler{Proxy=proxy,UseProxy=true,UseCookies=false,AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
        }
        return await EgressProbe.Verify(_probeClient,timeoutSeconds,()=>HandshakeReplyReceived,_stop.Token);
    }
    internal async Task Stop()
    {
        if(_process is null)return;
        NativeGuard.SuspendTun();
        if(!_process.HasExited){
            _process.StandardInput.Close();
            try{await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
            catch{_process.Kill(true);await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));}
        }
        _process.Dispose();_process=null;
        _probeClient?.Dispose();_probeClient=null;StandbyCapable=false;TunActive=false;
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
