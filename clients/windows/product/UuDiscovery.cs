using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace OracleProxy.Product;
internal sealed record UuIssue(string Path,string Code,string Detail="");
internal sealed record UuInventory(string[] Paths,int Candidates,int Rejected,UuIssue[] Issues);
internal static class UuDiscovery
{
    internal static string[] InstallationRoots()
    {
        var roots=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}){
            using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
            using(var setup=machine.OpenSubKey(@"SOFTWARE\Netease\GameViewerSetup"))
                if(setup is not null)foreach(string key in setup.GetValueNames())
                    if(setup.GetValue(key) is string value)AddRoot(value,roots);
            using var uninstall=machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if(uninstall is null)continue;
            foreach(string name in uninstall.GetSubKeyNames()){
                using var app=uninstall.OpenSubKey(name);string label=app?.GetValue("DisplayName") as string ?? "";
                if(!Related(label))continue;
                AddRoot(app?.GetValue("InstallLocation") as string ?? "",roots);
                AddRoot(app?.GetValue("DisplayIcon") as string ?? "",roots);
            }
        }
        // Discover per-user installations from loaded profiles as well. The
        // SYSTEM HKCU is not the interactive user's hive. Every path still has
        // to pass the same publisher, ownership and ACL checks below.
        using(var profiles=RegistryKey.OpenBaseKey(RegistryHive.Users,RegistryView.Registry64))
        foreach(string sid in profiles.GetSubKeyNames().Where(s=>s.StartsWith("S-1-5-21-",StringComparison.Ordinal) && !s.EndsWith("_Classes",StringComparison.Ordinal))){
            using var uninstall=profiles.OpenSubKey(sid+@"\Software\Microsoft\Windows\CurrentVersion\Uninstall");
            if(uninstall is null)continue;
            foreach(string name in uninstall.GetSubKeyNames()){
                using var app=uninstall.OpenSubKey(name);
                if(!Related(app?.GetValue("DisplayName") as string ?? ""))continue;
                AddRoot(app?.GetValue("InstallLocation") as string ?? "",roots);
                AddRoot(app?.GetValue("DisplayIcon") as string ?? "",roots);
            }
        }
        foreach(var process in Process.GetProcesses())using(process){
            try{if(Related(process.ProcessName))AddRoot(process.MainModule?.FileName ?? "",roots);}catch{ /* counted through installation records when available */ }
        }
        return roots.ToArray();
    }
    internal static UuInventory Discover()
    {
        var roots=InstallationRoots();
        var valid=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int count=0,rejected=0;var issues=new List<UuIssue>();
        void Issue(UuIssue issue){if(issues.Count<6 && !issues.Any(i=>i.Path==issue.Path && i.Code==issue.Code))issues.Add(issue with{Path=issue.Path.Length>256?issue.Path[..256]:issue.Path});}
        foreach(string root in roots){
            try{
                Platform.NoLinks(root);
                var options=new EnumerationOptions{RecurseSubdirectories=true,MaxRecursionDepth=4,IgnoreInaccessible=false,AttributesToSkip=FileAttributes.ReparsePoint};
                foreach(string path in Directory.EnumerateFiles(root,"*.exe",options)){
                    if(++count>256)throw new IOException("UU_INVENTORY_LIMIT");
                    var issue=Inspect(path);if(issue is null)valid.Add(Path.GetFullPath(path));else{rejected++;Issue(issue);}
                }
            }catch(Exception error){rejected++;Issue(new(root,error is IOException && error.Message=="REPARSE_POINT_REJECTED"?"UU_REPARSE_POINT":"UU_DIRECTORY_UNREADABLE"));}
        }
        return new(valid.Order(StringComparer.OrdinalIgnoreCase).ToArray(),Math.Max(count,roots.Length),rejected,issues.ToArray());
    }
    private static bool Related(string name)=>name.Contains("GameViewer",StringComparison.OrdinalIgnoreCase)||name.Contains("UURemote",StringComparison.OrdinalIgnoreCase)||name.Contains("UU远程",StringComparison.OrdinalIgnoreCase);
    private static void AddRoot(string value,HashSet<string> roots)
    {
        try{
            string p=Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
            if(p.Contains(","))p=p.Split(',')[0].Trim('"');
            if(!Path.IsPathFullyQualified(p)||p.StartsWith(@"\\"))return;
            if(File.Exists(p))p=Path.GetDirectoryName(p)!;
            if(Directory.Exists(p)&&Related(p)&&Path.GetPathRoot(p)!=p)roots.Add(Path.TrimEndingDirectorySeparator(Path.GetFullPath(p)));
        }catch{}
    }
    internal static bool Trusted(string path)=>Inspect(path) is null;
    internal static UuIssue? Inspect(string path)
    {
        try{
            var file=new FileInfo(path);if(!file.Exists||file.Length is <1024 or >300_000_000)return new(path,"UU_EXECUTABLE_UNREADABLE");
            if(file.Attributes.HasFlag(FileAttributes.ReparsePoint))return new(path,"UU_REPARSE_POINT");
            Platform.NoLinks(file.DirectoryName!);
            var fileSecurity=file.GetAccessControl();
            if(!TrustedOwner(fileSecurity))return new(path,"UU_EXECUTABLE_OWNER_UNTRUSTED");
            if(UnsafeWriter(fileSecurity))return new(path,"UU_EXECUTABLE_WRITABLE");
            // A protected directory can contain a separately writable file;
            // verify both ownership and effective object ACEs, including the
            // executable itself, before granting a path-based exception.
            for(var dir=file.Directory;dir?.Parent is not null;dir=dir.Parent){
                var security=dir.GetAccessControl();
                if(!TrustedOwner(security))return new(dir.FullName,"UU_DIRECTORY_OWNER_UNTRUSTED");
                if(UnsafeWriter(security))return new(dir.FullName,"UU_DIRECTORY_WRITABLE");
            }
            return SignatureIssue(path);
        }catch(IOException error) when(error.Message=="REPARSE_POINT_REJECTED"){return new(path,"UU_REPARSE_POINT");}
        catch(System.Security.Cryptography.CryptographicException){return new(path,"UU_SIGNATURE_UNREADABLE");}
        catch{return new(path,"UU_TRUST_INSPECTION_FAILED");}
    }
    internal static UuIssue? SignatureIssue(string path)
    {
        try{
            using var certificate=new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            string publisher=certificate.GetNameInfo(X509NameType.SimpleName,false);
            if(publisher is not ("NetEase (Hangzhou) Network Co., Ltd" or "NetEase(Hangzhou) Network Co. Ltd." or "NetEase (Hangzhou) Network Co., Ltd." or "Hangzhou NetEase Leihuo Technology Co., Ltd."))return new(path,"UU_PUBLISHER_UNRECOGNIZED");
            int status=VerifySignature(path);
            return status==0?null:new(path,"UU_SIGNATURE_NOT_VERIFIED","0x"+unchecked((uint)status).ToString("X8"));
        }catch{return new(path,"UU_SIGNATURE_UNREADABLE");}
    }
    internal static bool TrustedOwner(FileSystemSecurity security)=>
        security.GetOwner(typeof(SecurityIdentifier))?.Value is "S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    internal static bool UnsafeWriter(FileSystemSecurity security)=>security.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(rule=>
        !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) && rule.AccessControlType==AccessControlType.Allow &&
        rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464") &&
        (rule.FileSystemRights&(FileSystemRights.WriteData|FileSystemRights.CreateDirectories|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0);
    [StructLayout(LayoutKind.Sequential)]private struct TrustFile{public uint Size;public IntPtr Path,Handle,Subject;}
    [StructLayout(LayoutKind.Sequential)]private struct TrustData{public uint Size;public IntPtr Policy,Sip;public uint Ui,Revocation,Choice;public IntPtr File;public uint State;public IntPtr StateData,Url;public uint Flags,Context;public IntPtr Signature;}
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
    private static int VerifySignature(string path)
    {
        IntPtr name=Marshal.StringToHGlobalUni(path),file=Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        try{
            Marshal.StructureToPtr(new TrustFile{Size=(uint)Marshal.SizeOf<TrustFile>(),Path=name},file,false);
            var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),Ui=2,Choice=1,File=file,Flags=0x1000};
            var action=new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");return WinVerifyTrust(IntPtr.Zero,ref action,ref data);
        }finally{Marshal.FreeHGlobal(file);Marshal.FreeHGlobal(name);}
    }
}
