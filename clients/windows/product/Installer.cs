using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
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
    private static bool Registered(){using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Platform.Service);return key is not null;}
    private static void Stop()
    {
        VerifyService();
        if(Registered()){
            using var service=new ServiceController(Platform.Service);
            if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(25));}
        }
        if(!File.Exists(Platform.Exe))return;
        // SCM status can become Stopped just before Windows unloads DLLs.
        for(int i=0;i<150;i++){try{using var f=File.Open(Platform.Exe,FileMode.Open,FileAccess.ReadWrite,FileShare.None);return;}catch(IOException){Thread.Sleep(100);}}
        throw new IOException("SERVICE_IMAGE_STILL_IN_USE");
    }
    [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server,int session,int information,out IntPtr value,out int bytes);
    [DllImport("wtsapi32.dll")]private static extern void WTSFreeMemory(IntPtr value);
    private static string InteractiveAccountPart(int session,int information)
    {
        if(!WTSQuerySessionInformation(IntPtr.Zero,session,information,out var value,out int size))throw new IOException("INTERACTIVE_OWNER_UNAVAILABLE");
        try{return size>2?Marshal.PtrToStringUni(value)??"":"";}finally{WTSFreeMemory(value);}
    }
    internal static Task InstallInteractive()
    {
        // UAC may run Setup under different administrator credentials. Bind
        // fresh installs to the real desktop session, never USERNAME/env vars.
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        int session=Process.GetCurrentProcess().SessionId;
        if(session==0)throw new IOException("INTERACTIVE_OWNER_UNAVAILABLE");
        string user=InteractiveAccountPart(session,5),domain=InteractiveAccountPart(session,7);
        if(string.IsNullOrWhiteSpace(user))throw new IOException("INTERACTIVE_OWNER_UNAVAILABLE");
        var account=string.IsNullOrWhiteSpace(domain)?new NTAccount(user):new NTAccount(domain,user);
        var owner=(SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
        return InstallDesktop(owner.Value);
    }
    internal static Task InstallDesktop(string owner)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        _=new SecurityIdentifier(owner);
        Platform.VerifyBundle(AppContext.BaseDirectory);
        string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"OracleProxyDesktop");
        string marker=Path.Combine(root,"desktop.marker");
        Platform.NoLinks(root);
        if(Directory.Exists(root)){
            // A fixed Program Files pathname alone is not a trust boundary.
            // Never adopt or silently repair another installer's writable tree.
            Platform.VerifyProtected(root);
            if(File.Exists(marker)){
                var file=new FileInfo(marker);
                if(file.Attributes.HasFlag(FileAttributes.ReparsePoint) || file.Length>64 || File.ReadAllText(marker)!="OracleProxy.Desktop.v1")throw new IOException("DESKTOP_DIRECTORY_COLLISION");
            }else if(Directory.EnumerateFileSystemEntries(root).Any())throw new IOException("DESKTOP_DIRECTORY_COLLISION");
        }else{
            Directory.CreateDirectory(root);
            Platform.Protect(root,true);
        }
        if(!File.Exists(marker))Platform.WriteAtomic(marker,System.Text.Encoding.UTF8.GetBytes("OracleProxy.Desktop.v1"));
        return Install(owner);
    }
    internal static async Task Install(string owner)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        _=new SecurityIdentifier(owner);VerifyService();bool registered=Registered();
        string source=AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        if(string.Equals(source,Platform.Root,StringComparison.OrdinalIgnoreCase))throw new IOException("USE_PORTABLE_PACKAGE_TO_UPGRADE");
        Platform.VerifyBundle(source);Platform.NoLinks(Platform.Root);Platform.NoLinks(Platform.StateRoot);
        bool existing=Directory.Exists(Platform.Root);string previous=Path.Combine(Platform.Root,"previous");
        if(existing){Platform.VerifyProtected(Platform.Root);if(!File.Exists(Path.Combine(Platform.Root,"product.marker")))throw new IOException("INSTALL_DIRECTORY_COLLISION");}
        else{
            Directory.CreateDirectory(Platform.Root);Platform.Protect(Platform.Root,true);
            Platform.WriteAtomic(Path.Combine(Platform.Root,"product.marker"),System.Text.Encoding.UTF8.GetBytes("OracleProxy.Product.v1"));
        }
        if(Directory.Exists(Platform.StateRoot))Platform.VerifyProtected(Platform.StateRoot);
        else{Directory.CreateDirectory(Platform.StateRoot);Platform.Protect(Platform.StateRoot,false);}
        if(!File.Exists(Path.Combine(Platform.Root,"owner.sid")))Platform.WriteAtomic(Path.Combine(Platform.Root,"owner.sid"),System.Text.Encoding.UTF8.GetBytes(owner));
        bool backedUp=false;
        try{
            Stop();
            if(registered && Files.All(name=>File.Exists(Path.Combine(Platform.Root,name)))){
                Directory.CreateDirectory(previous);Platform.Protect(previous,true);
                foreach(string name in Files)File.Copy(Path.Combine(Platform.Root,name),Path.Combine(previous,name),true);
                backedUp=true;
            }
            foreach(string name in Files)File.Copy(Path.Combine(source,name=="OracleProxy.Service.exe"?"OracleProxy.exe":name),Path.Combine(Platform.Root,name),true);
            if(!registered)Sc("create",Platform.Service,"binPath=",Image,"start=","auto","obj=","LocalSystem","depend=","BFE/Tcpip","DisplayName=","Oracle Proxy VPN");
            Platform.ServiceEnvironment(Platform.Service);
            Sc("failure",Platform.Service,"reset=","300","actions=","restart/3000/restart/5000/restart/10000");
            Sc("start",Platform.Service);
            using var service=new ServiceController(Platform.Service);service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(25));
            bool ready=false;for(int i=0;i<20;i++){try{await ControlPipe.Send("Status");ready=true;break;}catch{await Task.Delay(500);}}
            if(!ready)throw new IOException("SERVICE_START_FAILED");
        }catch{
            if(registered){
                try{Stop();if(backedUp)foreach(string name in Files)File.Copy(Path.Combine(previous,name),Path.Combine(Platform.Root,name),true);Sc("start",Platform.Service);}catch{}
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
        Stop();
        try{Platform.ClearBundleCache();}catch{try{Sc("start",Platform.Service);}catch{}throw;}
        Sc("delete",Platform.Service);
        // Fixed allowlist only: leave unexpected files for manual inspection.
        foreach(string name in Files.Concat(new[]{"owner.sid","product.marker","owner.sid.pending","product.marker.pending","diagnostics.json","diagnostics.json.pending"})){
            string path=Path.Combine(Platform.Root,name);if(File.Exists(path)){if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");File.Delete(path);}}
        string previous=Path.Combine(Platform.Root,"previous");if(Directory.Exists(previous)){Platform.VerifyProtected(previous);foreach(string name in Files)File.Delete(Path.Combine(previous,name));if(!Directory.EnumerateFileSystemEntries(previous).Any())Directory.Delete(previous);}
        Platform.VerifyProtected(Platform.StateRoot);
        foreach(string name in new[]{"state.dpapi","state.dpapi.pending"})File.Delete(Path.Combine(Platform.StateRoot,name));
        foreach(string path in Directory.EnumerateFiles(Platform.StateRoot,"state.recovery-*.dpapi")){
            if(System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(path),@"^state\.recovery-[a-f0-9]{32}\.dpapi$")){
                if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");File.Delete(path);
            }
        }
        if(!Directory.EnumerateFileSystemEntries(Platform.StateRoot).Any())Directory.Delete(Platform.StateRoot);
        if(!Directory.EnumerateFileSystemEntries(Platform.Root).Any())Directory.Delete(Platform.Root);
    }
    internal static async Task Recover()
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        VerifyService();Platform.VerifyProtected(Platform.Root);Platform.VerifyBundle(Platform.Root);
        Stop();
        string image="\""+Platform.Exe+"\" --recovery-service";
        using(var existing=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+RecoveryService.Name)){
            if(existing is not null && existing.GetValue("ImagePath") as string!=image)throw new IOException("RECOVERY_SERVICE_COLLISION");
            if(existing is null)Sc("create",RecoveryService.Name,"binPath=",image,"start=","demand","obj=","LocalSystem");
        }
        Platform.ServiceEnvironment(RecoveryService.Name);
        string diagnostic=Path.Combine(Platform.Root,"diagnostics.json");File.Delete(diagnostic);
        try{
            Sc("start",RecoveryService.Name);
            bool finished=false;
            for(int i=0;i<80;i++){
                using var helper=new ServiceController(RecoveryService.Name);
                if(helper.Status==ServiceControllerStatus.Stopped && File.Exists(diagnostic)){finished=true;break;}
                await Task.Delay(250);
            }
            if(!finished || System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(diagnostic))?["code"]?.GetValue<string>()!="RECOVERED_DIRECT")throw new IOException("RECOVERY_NOT_VERIFIED");
        }finally{
            using var helper=new ServiceController(RecoveryService.Name);
            if(helper.Status==ServiceControllerStatus.Stopped)Sc("delete",RecoveryService.Name);
        }
        Sc("start",Platform.Service);
    }
    internal static void ElevateUuPermissions(bool restore)
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add(restore?"--restore-uu-permissions":"--repair-uu-permissions");Process.Start(info);
    }
    internal static void ElevateRecovery()
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};info.ArgumentList.Add("--recover");Process.Start(info);
    }
    internal static void Elevate(bool uninstall)
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add(uninstall?"--uninstall":"--install");
        if(!uninstall)info.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
        Process.Start(info);
    }
}
