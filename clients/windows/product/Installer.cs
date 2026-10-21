using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
namespace OracleProxy.Product;
internal static class Installer
{
    private static readonly string[] Files=["OracleProxy.Service.exe","OracleProxy.Core.exe","OracleProxy.Guard.dll"];
    private static string Image=>"\""+Platform.Exe+"\" --service";
    private static void VerifyService()
    {
        using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Platform.Service);
        if(key is not null && key.GetValue("ImagePath") as string!=Image)throw new IOException("SERVICE_NAME_COLLISION");
    }
    private static void Sc(params string[] args){if(Platform.FixedCommand("sc.exe",args)!=0)throw new IOException("SERVICE_CONFIGURATION_FAILED");}
    private static void Stop()
    {
        VerifyService();using var service=new ServiceController(Platform.Service);
        if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(25));}
        // SCM status can become Stopped just before Windows unloads DLLs.
        for(int i=0;i<30;i++){try{using var f=File.Open(Platform.Exe,FileMode.Open,FileAccess.ReadWrite,FileShare.None);return;}catch(IOException){Thread.Sleep(100);}}
        throw new IOException("SERVICE_IMAGE_STILL_IN_USE");
    }
    internal static async Task Install(string owner)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        _=new SecurityIdentifier(owner);VerifyService();
        string source=AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        if(string.Equals(source,Platform.Root,StringComparison.OrdinalIgnoreCase))throw new IOException("USE_PORTABLE_PACKAGE_TO_UPGRADE");
        Platform.VerifyBundle(source);Platform.NoLinks(Platform.Root);Platform.NoLinks(Platform.StateRoot);
        bool existing=Directory.Exists(Platform.Root);string previous=Path.Combine(Platform.Root,"previous");
        if(existing){Platform.VerifyProtected(Platform.Root);if(!File.Exists(Path.Combine(Platform.Root,"product.marker")))throw new IOException("INSTALL_DIRECTORY_COLLISION");Stop();}
        else{Directory.CreateDirectory(Platform.Root);Platform.Protect(Platform.Root,true);}
        if(Directory.Exists(Platform.StateRoot))Platform.VerifyProtected(Platform.StateRoot);
        else{Directory.CreateDirectory(Platform.StateRoot);Platform.Protect(Platform.StateRoot,false);}
        if(existing){
            Directory.CreateDirectory(previous);Platform.Protect(previous,true);
            foreach(string name in Files)File.Copy(Path.Combine(Platform.Root,name),Path.Combine(previous,name),true);
        }
        try{
            foreach(string name in Files)File.Copy(Path.Combine(source,name=="OracleProxy.Service.exe"?"OracleProxy.exe":name),Path.Combine(Platform.Root,name),true);
            if(!existing)Platform.WriteAtomic(Path.Combine(Platform.Root,"owner.sid"),System.Text.Encoding.UTF8.GetBytes(owner));
            Platform.WriteAtomic(Path.Combine(Platform.Root,"product.marker"),System.Text.Encoding.UTF8.GetBytes("OracleProxy.Product.v1"));
            if(!existing)Sc("create",Platform.Service,"binPath=",Image,"start=","auto","obj=","LocalSystem","depend=","BFE/Tcpip","DisplayName=","Oracle Proxy VPN");
            Sc("failure",Platform.Service,"reset=","86400","actions=","restart/3000/restart/10000/restart/30000");
            Sc("start",Platform.Service);
            using var service=new ServiceController(Platform.Service);service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(25));
            bool ready=false;for(int i=0;i<20;i++){try{await ControlPipe.Send("Status");ready=true;break;}catch{await Task.Delay(500);}}
            if(!ready)throw new IOException("SERVICE_START_FAILED");
        }catch{
            if(existing){
                try{Stop();foreach(string name in Files)File.Copy(Path.Combine(previous,name),Path.Combine(Platform.Root,name),true);Sc("start",Platform.Service);}catch{}
            }
            // Preserve state and owned firewall on failure. Never manufacture
            // an Off intent or clear protection as an installation side effect.
            throw;
        }
    }
    internal static async Task Remove()
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();VerifyService();Platform.VerifyProtected(Platform.Root);
        var status=await ControlPipe.Send("Disconnect");
        if(status["ok"]?.GetValue<bool>()!=true || status["mode"]?.GetValue<string>()!="disconnected")throw new IOException("SAFE_DISCONNECT_REQUIRED");
        Stop();Sc("delete",Platform.Service);
        // Fixed allowlist only: leave unexpected files for manual inspection.
        foreach(string name in Files.Concat(new[]{"owner.sid","product.marker","owner.sid.pending","product.marker.pending","diagnostics.json","diagnostics.json.pending"})){
            string path=Path.Combine(Platform.Root,name);if(File.Exists(path)){if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");File.Delete(path);}}
        string previous=Path.Combine(Platform.Root,"previous");if(Directory.Exists(previous)){Platform.VerifyProtected(previous);foreach(string name in Files)File.Delete(Path.Combine(previous,name));if(!Directory.EnumerateFileSystemEntries(previous).Any())Directory.Delete(previous);}
        Platform.VerifyProtected(Platform.StateRoot);
        foreach(string name in new[]{"state.dpapi","state.dpapi.pending"})File.Delete(Path.Combine(Platform.StateRoot,name));
        if(!Directory.EnumerateFileSystemEntries(Platform.StateRoot).Any())Directory.Delete(Platform.StateRoot);
        if(!Directory.EnumerateFileSystemEntries(Platform.Root).Any())Directory.Delete(Platform.Root);
    }
    internal static void Elevate(bool uninstall)
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add(uninstall?"--uninstall":"--install");
        if(!uninstall)info.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
        Process.Start(info);
    }
}
