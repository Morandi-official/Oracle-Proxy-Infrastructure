using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal sealed class CoreProcess : IDisposable
{
    private Process? _process;
    private IntPtr _job;
    private string _probeSecret="";
    internal bool Running=>_process is not null && !_process.HasExited;
    internal async Task Start(JsonObject state,DurableState secret)
    {
        if(Running)throw new IOException("CORE_ALREADY_RUNNING");
        if(_process is not null)await Stop();
        Platform.VerifyBundle(Platform.Root);_probeSecret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var info=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Platform.Root,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        // A suspended native launch + job assignment would narrow the creation
        // race further. Persistent WFP already blocks direct user traffic.
        _process=Process.Start(info) ?? throw new IOException("CORE_START_FAILED");
        _job=CreateJobObject(IntPtr.Zero,null);if(_job==IntPtr.Zero)throw new IOException("JOB_CREATE_FAILED");
        var limits=new JobLimits();limits.Basic.LimitFlags=0x2000; // KILL_ON_JOB_CLOSE
        if(!SetInformationJobObject(_job,9,ref limits,(uint)Marshal.SizeOf<JobLimits>()) || !AssignProcessToJobObject(_job,_process.Handle))throw new IOException("JOB_ASSIGN_FAILED");
        _process.ErrorDataReceived+=(_,_)=>{};_process.BeginErrorReadLine();
        await _process.StandardInput.WriteLineAsync(CoreConfig.Build(state,secret,_probeSecret).ToJsonString());await _process.StandardInput.FlushAsync();
        string? ready=await _process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
        if(ready!="READY")throw new IOException("CORE_START_FAILED");
    }
    internal async Task<long> Probe()
    {
        if(!Running)throw new IOException("CORE_NOT_RUNNING");
        var proxy=new WebProxy("socks5://127.0.0.1:28083"){Credentials=new NetworkCredential("service",_probeSecret)};
        using var client=new HttpClient(new SocketsHttpHandler{Proxy=proxy,UseProxy=true,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(12)};
        var timer=Stopwatch.StartNew();string body=await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
        if(body.Length>8192 || !body.Split('\n').Any(line=>line=="ip=152.67.156.100"))throw new IOException("ORACLE_EGRESS_NOT_VERIFIED");
        return timer.ElapsedMilliseconds;
    }
    internal async Task Stop()
    {
        if(_process is null)return;
        if(!_process.HasExited){
            _process.StandardInput.Close();
            try{await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));}
            catch{_process.Kill(true);await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));}
        }
        _process.Dispose();_process=null;
        if(_job!=IntPtr.Zero){CloseHandle(_job);_job=IntPtr.Zero;}
        _probeSecret="";
    }
    public void Dispose(){try{Stop().GetAwaiter().GetResult();}catch{}if(_job!=IntPtr.Zero){CloseHandle(_job);_job=IntPtr.Zero;}}
    [StructLayout(LayoutKind.Sequential)]private struct BasicLimits{public long ProcessTime,JobTime;public uint LimitFlags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
    [StructLayout(LayoutKind.Sequential)]private struct IoCounters{public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)]private struct JobLimits{public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]private static extern IntPtr CreateJobObject(IntPtr security,string? name);
    [DllImport("kernel32.dll")]private static extern bool SetInformationJobObject(IntPtr job,int kind,ref JobLimits data,uint length);
    [DllImport("kernel32.dll")]private static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")]private static extern bool CloseHandle(IntPtr handle);
}
