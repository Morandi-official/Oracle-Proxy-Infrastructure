using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal static class Installer
{
    private static readonly string[] Files=["Proxy.Service.exe","Proxy.Core.exe","Proxy.Guard.dll"];
    private static readonly string[] LegacyFiles=["OracleProxy.Service.exe","OracleProxy.Core.exe","OracleProxy.Guard.dll"];
    private static string LegacyImage=>"\""+Path.Combine(Platform.Root,LegacyFiles[0])+"\" --service";
    private static string Image=>"\""+Platform.Exe+"\" --service";
    private static void VerifyService()
    {
        using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Platform.Service);
        if(key is not null && key.GetValue("ImagePath") as string!=Image && key.GetValue("ImagePath") as string!=LegacyImage)throw new IOException("SERVICE_NAME_COLLISION");
    }
    private static void Sc(params string[] args){if(Platform.FixedCommand("sc.exe",args)!=0)throw new IOException("SERVICE_CONFIGURATION_FAILED");}
    private static bool Registered(){using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Platform.Service);return key is not null;}
    private static void Stop()
    {
        VerifyService();
        if(Registered()){
            using var service=new ServiceController(Platform.Service);
            if(service.Status!=ServiceControllerStatus.Stopped){
                if(service.Status!=ServiceControllerStatus.StopPending){
                    try{service.Stop();}
                    catch(Exception error)when(error is InvalidOperationException or System.ComponentModel.Win32Exception){
                        service.Refresh();
                        // A verified Off reply can start graceful self-stop
                        // between our status read and SCM control request.
                        if(service.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))throw;
                    }
                }
                service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(25));
            }
        }
        string installedExe=File.Exists(Platform.Exe)?Platform.Exe:Path.Combine(Platform.Root,LegacyFiles[0]);
        if(!File.Exists(installedExe))return;
        // SCM Stopped precedes final process teardown. Wait for only our
        // exact SYSTEM service image before deleting its extraction cache.
        foreach(var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(installedExe)))using(process){
            try{
                if(process.HasExited || process.SessionId!=0)continue;
                if(string.Equals(process.MainModule?.FileName,installedExe,StringComparison.OrdinalIgnoreCase) && !process.WaitForExit(10000))throw new IOException("SERVICE_PROCESS_STILL_RUNNING");
            }catch(InvalidOperationException)when(process.HasExited){}
        }
        for(int i=0;i<150;i++){try{using var f=File.Open(installedExe,FileMode.Open,FileAccess.ReadWrite,FileShare.None);return;}catch(IOException){Thread.Sleep(100);}}
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
        bool legacy;using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Platform.Service)){legacy=registered && key?.GetValue("ImagePath") as string==LegacyImage;}
        string[] previousFiles=legacy?LegacyFiles:Files;string oldImage=legacy?LegacyImage:Image;
        bool backedUp=false;
        try{
            Stop();
            if(registered && previousFiles.All(name=>File.Exists(Path.Combine(Platform.Root,name)))){
                Directory.CreateDirectory(previous);Platform.Protect(previous,true);
                foreach(string name in previousFiles)File.Copy(Path.Combine(Platform.Root,name),Path.Combine(previous,name),true);
                backedUp=true;
            }
            foreach(string name in Files)File.Copy(Platform.BundleFile(source,name=="Proxy.Service.exe"?"Proxy.exe":name),Path.Combine(Platform.Root,name),true);
            if(!registered)Sc("create",Platform.Service,"binPath=",Image,"start=","auto","obj=","LocalSystem","depend=","BFE/Tcpip","DisplayName=","Proxy VPN");
            else Sc("config",Platform.Service,"binPath=",Image,"DisplayName=","Proxy VPN");
            // Only query and start are delegated to the registered desktop owner.
            // No stop, configuration, DACL, or arbitrary service rights.
            Sc("sdset",Platform.Service,"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;"+File.ReadAllText(Path.Combine(Platform.Root,"owner.sid")).Trim()+")");
            Platform.ServiceEnvironment(Platform.Service);
            Sc("failure",Platform.Service,"reset=","300","actions=","restart/3000/restart/5000/restart/10000");
            Sc("start",Platform.Service);
            using var service=new ServiceController(Platform.Service);service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(25));
            bool ready=false;for(int i=0;i<20;i++){try{await ControlPipe.Send("Status");ready=true;break;}catch{await Task.Delay(500);}}
            if(!ready)throw new IOException("SERVICE_START_FAILED");
            // Retire legacy payloads only after the replacement service answers.
            foreach(string name in LegacyFiles)try{File.Delete(Path.Combine(Platform.Root,name));File.Delete(Path.Combine(previous,name));}catch(IOException){}
        }catch{
            if(registered){
                try{Stop();if(backedUp)foreach(string name in previousFiles)File.Copy(Path.Combine(previous,name),Path.Combine(Platform.Root,name),true);Sc("config",Platform.Service,"binPath=",oldImage);Sc("start",Platform.Service);}catch{}
            }
            // Preserve state and owned firewall on failure. Never manufacture
            // an Off intent or clear protection as an installation side effect.
            throw;
        }
    }
    private static bool RetiringPipeFailure(IOException error)=>
        error.Message is "SERVICE_BUSY" or "INCOMPLETE_FRAME" or "SERVICE_IDENTITY_NOT_VERIFIED" ||
        unchecked((uint)error.HResult) is 0x8007006D or 0x800700E8 or 0x800700E9; // broken/closing/disconnected Windows pipe
    private static async Task<JsonObject> DisconnectForMaintenance()
    {
        for(int attempt=0;;attempt++){
            try{return await ControlPipe.Send("Disconnect");}
            catch(IOException error)when(attempt==0 && RetiringPipeFailure(error)){
                // The previous GUI may have exited before this installer could
                // authenticate its retiring pipe. Retry only idempotent Off,
                // after SCM proves stop; each new pipe is authenticated anew.
                // Pipe cancellation can precede SCM StopPending. Waiting is
                // read-only; a still-running service times out, never replays.
                await ControlPipe.WaitStopped(CancellationToken.None);VerifyService();
            }
        }
    }
    internal static async Task Remove()
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();VerifyService();Platform.VerifyProtected(Platform.Root);
        var status=await DisconnectForMaintenance();
        if(status["ok"]?.GetValue<bool>()!=true || status["mode"]?.GetValue<string>()!="disconnected")throw new IOException("SAFE_DISCONNECT_REQUIRED");
        Stop();
        try{Platform.ClearBundleCache();}catch{try{Sc("start",Platform.Service);}catch{}throw;}
        Sc("delete",Platform.Service);
        // Fixed allowlist only: leave unexpected files for manual inspection.
        foreach(string name in Files.Concat(LegacyFiles).Concat(new[]{"owner.sid","product.marker","owner.sid.pending","product.marker.pending","diagnostics.json","diagnostics.json.pending"})){
            string path=Path.Combine(Platform.Root,name);if(File.Exists(path)){if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");File.Delete(path);}}
        string previous=Path.Combine(Platform.Root,"previous");if(Directory.Exists(previous)){Platform.VerifyProtected(previous);foreach(string name in Files.Concat(LegacyFiles))File.Delete(Path.Combine(previous,name));if(!Directory.EnumerateFileSystemEntries(previous).Any())Directory.Delete(previous);}
        Platform.VerifyProtected(Platform.StateRoot);
        foreach(string name in new[]{"state.dpapi","state.dpapi.pending","tun-owner.json","tun-owner.json.pending"}){
            string path=Path.Combine(Platform.StateRoot,name);
            if(File.Exists(path)){
                if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");
                File.Delete(path);
            }
        }
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
            // Fixed adapter recovery has its own 20s child deadline, followed by
            // the unchanged 3s native absence audit and DPAPI commit. Give this
            // complete local operation 45s, not the former 20s polling budget.
            for(int i=0;i<180;i++){
                using var helper=new ServiceController(RecoveryService.Name);
                if(helper.Status==ServiceControllerStatus.Stopped && File.Exists(diagnostic)){finished=true;break;}
                await Task.Delay(250);
            }
            if(!finished){
                using var helper=new ServiceController(RecoveryService.Name);
                if(helper.Status!=ServiceControllerStatus.Stopped){
                    helper.Stop();helper.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(12));
                }
                // Stop waits for cancellation/child exit. A commit that won the
                // race may already be complete; verify its fixed result below.
                if(!File.Exists(diagnostic))throw new IOException("RECOVERY_DEADLINE");
            }
            // Preserve the one-shot helper's already-sanitized reason when
            // Program records the outer setup failure. Never export arbitrary
            // diagnostic content, exception messages, paths, or credentials.
            string? helperCode=null;
            try{
                var value=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(diagnostic))?["code"];
                if(value is System.Text.Json.Nodes.JsonValue text && text.TryGetValue<string>(out var code))helperCode=code;
            }catch(System.Text.Json.JsonException){}
            if(helperCode!="RECOVERED_DIRECT")throw new IOException(
                helperCode is {Length:>0 and <=48} && helperCode.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')
                ?"RECOVERY_"+helperCode:"RECOVERY_RESULT_INVALID");
        }finally{
            using var helper=new ServiceController(RecoveryService.Name);
            if(helper.Status==ServiceControllerStatus.Stopped){
                // Even a failed recovery must restore the authenticated control
                // service. It reloads persisted recovery intent and retains the
                // guard; restarting does not claim that direct access is safe.
                try{Sc("delete",RecoveryService.Name);}
                finally{Sc("start",Platform.Service);}
            }
        }
    }
    internal static async Task<int> ElevateUuPermissionsAsync(bool restore,CancellationToken cancel=default)
    {
        cancel.ThrowIfCancellationRequested();
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add(restore?"--restore-uu-permissions":"--repair-uu-permissions");
        Process process;
        try{process=Process.Start(info) ?? throw new IOException("UU_MAINTENANCE_NOT_STARTED");}
        catch(System.ComponentModel.Win32Exception error) when(error.NativeErrorCode==1223){return 4;}
        using(process){
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);
            deadline.CancelAfter(TimeSpan.FromMinutes(2));
            // This is an elevated, transactional ACL operation. Stop waiting on
            // cancellation, but never kill it halfway through its rollback.
            try{await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);}
            catch(OperationCanceledException){throw new IOException("UU_MAINTENANCE_RESULT_PENDING");}
            return process.ExitCode;
        }
    }
    private static readonly object RecoveryLock=new();
    private static Task<int>? _pendingRecovery;
    internal static Task<int> ElevateRecoveryAsync(CancellationToken cancel)
    {
        Task<int> pending;
        lock(RecoveryLock){
            if(_pendingRecovery is null || _pendingRecovery.IsCompleted)_pendingRecovery=RecoveryChild();
            pending=_pendingRecovery;
        }
        // Cancelling the GUI wait must not kill an elevated recovery worker.
        return pending.WaitAsync(cancel);
    }
    private static async Task<int> RecoveryChild()
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};info.ArgumentList.Add("--recover");
        Process process;
        try{process=Process.Start(info) ?? throw new IOException("RECOVERY_NOT_STARTED");}
        catch(System.ComponentModel.Win32Exception error)when(error.NativeErrorCode==1223){return 4;}
        using(process){await process.WaitForExitAsync().ConfigureAwait(false);return process.ExitCode;}
    }
    private static readonly object InstallLock=new();
    private static Task<int>? _pendingInstall;
    internal static Task<int> ElevateInstallAsync(CancellationToken cancel)
    {
        Task<int> pending;
        lock(InstallLock){
            // Cancelling the GUI wait must not interrupt file replacement or
            // rollback. A retry joins this same child while it is still running.
            if(_pendingInstall is null || _pendingInstall.IsCompleted)_pendingInstall=InstallChild();
            pending=_pendingInstall;
        }
        return pending.WaitAsync(cancel);
    }
    private static async Task<int> InstallChild()
    {
        Platform.VerifyBundle(AppContext.BaseDirectory);
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add("--install");info.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
        Process process;
        try{process=Process.Start(info) ?? throw new IOException("SERVICE_SETUP_NOT_STARTED");}
        catch(System.ComponentModel.Win32Exception error)when(error.NativeErrorCode==1223){return 4;}
        using(process){await process.WaitForExitAsync().ConfigureAwait(false);return process.ExitCode;}
    }
    internal static void Elevate(bool uninstall)
    {
        var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        info.ArgumentList.Add(uninstall?"--uninstall":"--install");
        if(!uninstall)info.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
        Process.Start(info);
    }
}
