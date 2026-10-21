using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace OracleProxy.Product;
internal sealed record UuInventory(string[] Paths,int Candidates,int Rejected);
internal static class UuDiscovery
{
    internal static UuInventory Discover()
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
        foreach(var process in Process.GetProcesses())using(process){
            try{if(Related(process.ProcessName))AddRoot(process.MainModule?.FileName ?? "",roots);}catch{ /* counted through installation records when available */ }
        }
        var valid=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int count=0,rejected=0;
        foreach(string root in roots){
            try{
                Platform.NoLinks(root);
                var options=new EnumerationOptions{RecurseSubdirectories=true,MaxRecursionDepth=4,IgnoreInaccessible=false,AttributesToSkip=FileAttributes.ReparsePoint};
                foreach(string path in Directory.EnumerateFiles(root,"*.exe",options)){
                    if(++count>256)throw new IOException("UU_INVENTORY_LIMIT");
                    if(Trusted(path))valid.Add(Path.GetFullPath(path));else rejected++;
                }
            }catch{rejected++;}
        }
        return new(valid.Order(StringComparer.OrdinalIgnoreCase).ToArray(),count,rejected);
    }
    private static bool Related(string name)=>name.Contains("GameViewer",StringComparison.OrdinalIgnoreCase)||name.Contains("UURemote",StringComparison.OrdinalIgnoreCase)||name.Contains("UU远程",StringComparison.OrdinalIgnoreCase);
    private static void AddRoot(string value,HashSet<string> roots)
    {
        try{
            string p=Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
            if(p.Contains(","))p=p.Split(',')[0].Trim('"');
            if(!Path.IsPathFullyQualified(p)||p.StartsWith(@"\\"))return;
            if(File.Exists(p))p=Path.GetDirectoryName(p)!;
            if(Directory.Exists(p)&&Related(p)&&Path.GetPathRoot(p)!=p)roots.Add(Path.GetFullPath(p));
        }catch{}
    }
    internal static bool Trusted(string path)
    {
        try{
            var file=new FileInfo(path);if(!file.Exists||file.Length is <1024 or >300_000_000||file.Attributes.HasFlag(FileAttributes.ReparsePoint))return false;
            // Refuse writable parents all the way to the volume root: a trusted
            // signature at discovery time is insufficient if a user can replace
            // a parent or DLL dependency after SYSTEM grants a path exception.
            for(var dir=file.Directory;dir?.Parent is not null;dir=dir.Parent){
                Platform.NoLinks(dir.FullName);
                foreach(FileSystemAccessRule rule in dir.GetAccessControl().GetAccessRules(true,true,typeof(SecurityIdentifier)))
                    if(!rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) && rule.AccessControlType==AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464") &&
                       (rule.FileSystemRights&(FileSystemRights.WriteData|FileSystemRights.CreateDirectories|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)return false;
            }
            using var certificate=new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            string publisher=certificate.GetNameInfo(X509NameType.SimpleName,false);
            if(publisher is not ("NetEase (Hangzhou) Network Co., Ltd" or "NetEase(Hangzhou) Network Co. Ltd." or "NetEase (Hangzhou) Network Co., Ltd." or "Hangzhou NetEase Leihuo Technology Co., Ltd."))return false;
            return VerifySignature(path);
        }catch{return false;}
    }
    [StructLayout(LayoutKind.Sequential)]private struct TrustFile{public uint Size;public IntPtr Path,Handle,Subject;}
    [StructLayout(LayoutKind.Sequential)]private struct TrustData{public uint Size;public IntPtr Policy,Sip;public uint Ui,Revocation,Choice;public IntPtr File;public uint State;public IntPtr StateData,Url;public uint Flags,Context;public IntPtr Signature;}
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
    private static bool VerifySignature(string path)
    {
        IntPtr name=Marshal.StringToHGlobalUni(path),file=Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        try{
            Marshal.StructureToPtr(new TrustFile{Size=(uint)Marshal.SizeOf<TrustFile>(),Path=name},file,false);
            var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),Ui=2,Choice=1,File=file,Flags=0x1000};
            var action=new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");return WinVerifyTrust(IntPtr.Zero,ref action,ref data)==0;
        }finally{Marshal.FreeHGlobal(file);Marshal.FreeHGlobal(name);}
    }
}
