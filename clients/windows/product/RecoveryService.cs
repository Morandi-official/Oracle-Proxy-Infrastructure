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
    internal RecoveryService(){ServiceName=Name;AutoLog=false;}
    protected override void OnStart(string[] args)=>Task.Run(async()=>{
        try{
            if(!Platform.IsSystem)throw new UnauthorizedAccessException();
            Platform.VerifyProtected(Platform.Root);Platform.VerifyProtected(Platform.StateRoot);Platform.VerifyBundle(Platform.Root);
            foreach(var process in Process.GetProcessesByName("OracleProxy.Core"))using(process){
                if(process.SessionId==0 && string.Equals(process.MainModule?.FileName,Platform.Core,StringComparison.OrdinalIgnoreCase)){
                    process.Kill(true);await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                }
            }
            await VpnRuntime.EnsureTunnelGone();
            DurableState state;
            try{state=DurableState.Load();}
            catch(Exception e)when(e is CryptographicException or JsonException){
                // Preserve the encrypted damaged record for diagnosis/rollback.
                File.Move(Path.Combine(Platform.StateRoot,"state.dpapi"),Path.Combine(Platform.StateRoot,"state.recovery-"+Guid.NewGuid().ToString("N")+".dpapi"));
                state=new DurableState();
            }
            state.ConnectIntent=false;state.RecoveryRequired=false;state.Save();
            try{NativeGuard.Clear();}
            catch{
                state.ConnectIntent=true;state.RecoveryRequired=true;state.Save();
                try{NativeGuard.Apply(state.UuPaths.Where(UuDiscovery.Trusted).ToArray());}catch{}
                throw;
            }
            Platform.WriteAtomic(Path.Combine(Platform.Root,"diagnostics.json"),JsonSerializer.SerializeToUtf8Bytes(new{schema=1,stage="recovery",code="RECOVERED_DIRECT",at=DateTimeOffset.UtcNow.ToUnixTimeSeconds()}));
        }catch(Exception error){Platform.RecordFailure("recovery",error);}
        finally{Stop();}
    });
}
