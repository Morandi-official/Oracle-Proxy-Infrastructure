using System.ServiceProcess;
namespace OracleProxy.Product;
internal sealed class VpnService : ServiceBase
{
    private readonly CancellationTokenSource _cancel=new();
    private Task? _worker;
    private VpnRuntime? _runtime;
    internal VpnService(){ServiceName=Platform.Service;AutoLog=false;CanShutdown=true;}
    protected override void OnStart(string[] args)
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        _worker=Task.Run(async ()=>{
            try{
                _runtime=new VpnRuntime();await _runtime.Initialize();
                var tasks=new[]{_runtime.Run(_cancel.Token),ControlPipe.Serve(_runtime,_cancel.Token)};
                await Task.WhenAny(tasks);
                if(!_cancel.IsCancellationRequested)Environment.Exit(3);
            }catch(OperationCanceledException)when(_cancel.IsCancellationRequested){}
            catch{Environment.Exit(3);} // SCM recovery; no raw exception/secret logs.
        });
    }
    protected override void OnStop(){_cancel.Cancel();try{_worker?.Wait(TimeSpan.FromSeconds(3));}catch{} _runtime?.Dispose();}
    protected override void OnShutdown()=>OnStop();
}
