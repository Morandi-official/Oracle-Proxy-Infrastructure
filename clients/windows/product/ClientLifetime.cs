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
    public bool ProductWindow {get;set;}
    internal bool SameProcess(ClientIdentity other)=>Pid==other.Pid && Started==other.Started && Sid==other.Sid;
    // Run under the pipe caller's identity. Both the installed and portable
    // editions execute the same managed image the installer staged as service.
    internal bool MatchesGuiImage()
    {
        try{
            using var process=Process.GetProcessById(Pid);
            string? path=process.MainModule?.FileName;
            if(process.StartTime.ToUniversalTime().Ticks!=Started || path is null ||
                !string.Equals(Path.GetFileName(path),"Proxy.exe",StringComparison.OrdinalIgnoreCase) ||
                !Path.IsPathFullyQualified(path) || path.StartsWith(@"\\",StringComparison.Ordinal) ||
                new DriveInfo(Path.GetPathRoot(path)!).DriveType==DriveType.Network)return false;
            if(new FileInfo(path).Length!=new FileInfo(Platform.Exe).Length)return false;
            using var installed=File.OpenRead(Platform.Exe);
            string digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(installed));
            return Platform.Pinned(path,digest) && !process.HasExited;
        }catch(Exception error)when(error is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or ArgumentException){return false;}
    }
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
    private bool _windowControlled;
    private readonly List<ClientIdentity> _closingWindows=[];
    private readonly List<ClientIdentity> _holderOwners=[];
    private bool HasHolderOwner=>_manageClientLifetime && _holderOwners.Any(x=>x.Alive()==true);
    private void RememberHolderOwner(ClientIdentity identity){
        _holderOwners.RemoveAll(x=>x.Alive()!=true);
        if(identity.ProductWindow && !_holderOwners.Any(x=>x.SameProcess(identity)))_holderOwners.Add(identity);
    }
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
        _closingWindows.RemoveAll(x=>x.Alive()==false);
        if(_closingWindows.Any(x=>x.SameProcess(identity)))throw new IOException("CLIENT_WINDOW_CLOSING");
        _secret.UiClients=_secret.UiClients.Where(x=>x.Alive()!=false && x.Sid==owner).ToArray();
        var attached=_secret.UiClients.FirstOrDefault(x=>x.SameProcess(identity));
        if(attached is null){
            if(_secret.UiClients.Length>=8)throw new IOException("TOO_MANY_CLIENT_WINDOWS");
            _secret.UiClients=[.._secret.UiClients,identity];_secret.Save();
        }else if(identity.ProductWindow && !attached.ProductWindow){
            attached.ProductWindow=true;_secret.Save();
        }
        if(identity.ProductWindow)RememberHolderOwner(identity);
        _hadClient=true;_idleSince=DateTimeOffset.UtcNow;
    }
    private bool DetachWindow(ClientIdentity client){
        if(!client.ProductWindow)throw new IOException("CLIENT_WINDOW_NOT_VERIFIED");
        _closingWindows.Add(client);
        _secret.UiClients=_secret.UiClients.Where(x=>!x.SameProcess(client) && x.Alive()!=false).ToArray();_secret.Save();
        _holderOwners.RemoveAll(x=>x.SameProcess(client) || x.Alive()!=true);
        return HasHolderOwner;
    }
    private async Task CheckClientLifetime()
    {
        if(!_manageClientLifetime)return;
        if(_windowControlled && !HasHolderOwner){
            await EndUdpDiagnostics();await Disconnect(keepPrepared:false);
            if(_secret.RememberLoginUntil==0)ForgetLogin();
            _shutdown.TrySetResult();return;
        }
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
