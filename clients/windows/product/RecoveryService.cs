using System.Diagnostics;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
namespace OracleProxy.Product;
// Fixed, one-shot SYSTEM recovery after an explicit local UAC request. It is
// never reachable through arbitrary paths or commands on the ordinary pipe.
internal sealed class RecoveryService : ServiceBase
{
    internal const string Name="OracleProxyRecovery";
    private readonly CancellationTokenSource _cancel=new();
    private readonly ManualResetEventSlim _finished=new(false);
    internal RecoveryService(){ServiceName=Name;AutoLog=false;}
    protected override void OnStart(string[] args)=>Task.Run(async()=>{
        try{
            if(!Platform.IsSystem)throw new UnauthorizedAccessException();
            _cancel.Token.ThrowIfCancellationRequested();
            Platform.VerifyServiceEnvironment();
            Platform.VerifyProtected(Platform.Root);Platform.VerifyProtected(Platform.StateRoot);Platform.VerifyBundle(Platform.Root);
            foreach(var process in Process.GetProcessesByName("OracleProxy.Core"))using(process){
                _cancel.Token.ThrowIfCancellationRequested();
                if(TunReceipt.IsOwnedCore(process)){
                    process.Kill(true);await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5),_cancel.Token);
                }
            }
            if(NativeGuard.TunPresent)await TunReceipt.RecoverOrphan(_cancel.Token);
            await VpnRuntime.EnsureTunnelRemoved();
            _cancel.Token.ThrowIfCancellationRequested();
            DurableState state;
            try{state=DurableState.Load();}
            catch(Exception e)when(e is CryptographicException or JsonException || e is IOException && e.Message=="STATE_CORRUPT"){
                // Preserve the encrypted damaged record for diagnosis/rollback.
                File.Move(Path.Combine(Platform.StateRoot,"state.dpapi"),Path.Combine(Platform.StateRoot,"state.recovery-"+Guid.NewGuid().ToString("N")+".dpapi"));
                state=new DurableState();
            }
            _cancel.Token.ThrowIfCancellationRequested();
            state.ConnectIntent=false;state.RecoveryRequired=false;state.Save();
            try{_cancel.Token.ThrowIfCancellationRequested();NativeGuard.Clear();}
            catch{
                state.ConnectIntent=true;state.RecoveryRequired=true;state.Save();
                try{NativeGuard.Apply(state.UuPaths.Where(UuDiscovery.Trusted).ToArray());}catch{}
                throw;
            }
            Platform.WriteAtomic(Path.Combine(Platform.Root,"diagnostics.json"),JsonSerializer.SerializeToUtf8Bytes(new{schema=1,stage="recovery",code="RECOVERED_DIRECT",at=DateTimeOffset.UtcNow.ToUnixTimeSeconds()}));
        }catch(OperationCanceledException){Platform.RecordFailure("recovery",new IOException("RECOVERY_CANCELLED"));}
        catch(Exception error){Platform.RecordFailure("recovery",error);}
        finally{_finished.Set();Stop();}
    });
    protected override void OnStop()
    {
        // The worker sets finished before its own Stop(), avoiding self-wait.
        // An external stop waits for the canceled fixed child/worker to finish
        // before SCM can report Stopped and the installer removes this helper.
        if(_finished.IsSet)return;
        RequestAdditionalTime(12000);_cancel.Cancel();
        if(!_finished.Wait(TimeSpan.FromSeconds(10)))Environment.Exit(3);
    }
}
