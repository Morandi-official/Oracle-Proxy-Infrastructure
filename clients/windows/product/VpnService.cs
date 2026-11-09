using System.ServiceProcess;
namespace OracleProxy.Product;
internal sealed class VpnService : ServiceBase
{
    private readonly CancellationTokenSource _cancel=new();
    private Task? _worker;
    private readonly ManualResetEventSlim _finished=new(false);
    private VpnRuntime? _runtime;
    internal VpnService(){ServiceName=Platform.Service;AutoLog=false;CanShutdown=true;}
    protected override void OnStart(string[] args)
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        Platform.VerifyServiceEnvironment();
        _worker=Task.Run(async ()=>{
            try{
                _runtime=new VpnRuntime(manageClientLifetime:true);await _runtime.Initialize();
                var tasks=new[]{_runtime.Run(_cancel.Token),ControlPipe.Serve(_runtime,_cancel.Token)};
                await Task.WhenAny(tasks.Append(_runtime.ShutdownRequested));
                if(_runtime.ShutdownRequested.IsCompleted){_cancel.Cancel();_runtime.BeginStop();}
                if(!_cancel.IsCancellationRequested)Environment.Exit(3);
                await Task.WhenAll(tasks);
            }catch(Exception)when(_cancel.IsCancellationRequested){
                // Named-pipe/HTTP teardown may surface IOException as well as
                // cancellation. An explicitly stopped service must not request
                // SCM crash recovery while the installer waits for its image.
            }
            catch(Exception error){Platform.RecordFailure("service",error);Environment.Exit(3);} // SCM recovery; no raw exception/secret logs.
            finally{_finished.Set();if(_runtime?.ShutdownRequested.IsCompleted==true)Stop();}
        });
    }
    protected override void OnStop(){if(_finished.IsSet){_runtime?.Dispose();return;}RequestAdditionalTime(30000);_cancel.Cancel();_runtime?.BeginStop();try{if(_worker?.Wait(TimeSpan.FromSeconds(25))==false)Environment.Exit(3);}catch{} _runtime?.Dispose();}
    protected override void OnShutdown()=>OnStop();
}
