using System.ComponentModel;
using System.Diagnostics;
namespace OracleProxy.Product;
// Stored only inside SYSTEM DPAPI state. A pipe-proven PID plus creation time
// identifies the same live controller across an intentional service restart.
internal sealed class ClientIdentity
{
    public int Pid {get;set;}
    public long Started {get;set;}
    public string Sid {get;set;}="";
    internal static ClientIdentity Capture(uint pid,string sid)
    {
        using var process=Process.GetProcessById(checked((int)pid));
        return new(){Pid=process.Id,Started=process.StartTime.ToUniversalTime().Ticks,Sid=sid};
    }
    internal bool? Alive()
    {
        try{using var process=Process.GetProcessById(Pid);return !process.HasExited && process.StartTime.ToUniversalTime().Ticks==Started;}
        catch(ArgumentException){return false;}
        catch(InvalidOperationException){return false;}
        catch(Win32Exception){return null;} // Uncertainty is not permission to open egress.
    }
}
internal sealed partial class VpnRuntime
{
    private readonly bool _manageClientLifetime;
    private bool _hadClient;
    private DateTimeOffset _idleSince=DateTimeOffset.UtcNow;
    private readonly TaskCompletionSource _shutdown=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task ShutdownRequested=>_shutdown.Task;
    internal VpnRuntime(bool manageClientLifetime=false){_manageClientLifetime=manageClientLifetime;}
    internal void ResponseDelivered(System.Text.Json.Nodes.JsonObject response)
    {
        if(_manageClientLifetime && response["shutdown_after_response"]?.GetValue<bool>()==true)_shutdown.TrySetResult();
    }
    private void Attach(ClientIdentity identity)
    {
        string owner=File.ReadAllText(Path.Combine(Platform.Root,"owner.sid")).Trim();
        if(identity.Sid!=owner)throw new UnauthorizedAccessException();
        _secret.UiClients=_secret.UiClients.Where(x=>x.Alive()!=false && x.Sid==owner).ToArray();
        if(!_secret.UiClients.Any(x=>x.Pid==identity.Pid && x.Started==identity.Started)){
            if(_secret.UiClients.Length>=8)throw new IOException("TOO_MANY_CLIENT_WINDOWS");
            _secret.UiClients=[.._secret.UiClients,identity];_secret.Save();
        }
        _hadClient=true;_idleSince=DateTimeOffset.UtcNow;
    }
    private async Task CheckClientLifetime()
    {
        if(!_manageClientLifetime)return;
        if(_secret.UiClients.Length>0){
            var remaining=_secret.UiClients.Where(x=>x.Alive()!=false).ToArray();
            if(remaining.Length!=_secret.UiClients.Length){_secret.UiClients=remaining;_secret.Save();}
            if(remaining.Length>0){_hadClient=true;return;}
        }
        // Only process termination (not a heartbeat timeout, sleep or network
        // outage) retires a GUI owner. A booted idle service gets startup grace.
        if(!_hadClient && DateTimeOffset.UtcNow-_idleSince<TimeSpan.FromSeconds(60))return;
        await EndUdpDiagnostics();await Disconnect(keepPrepared:false);
        if(_secret.RememberLoginUntil==0)ForgetLogin();
        _shutdown.TrySetResult();
    }
}
