using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace OracleProxy.Product;

internal static class Platform
{
    internal const string Service = "OracleProxyService";
    internal const string Pipe = "OracleProxy.Control.v1";
    internal static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"OracleProxy");
    internal static string StateRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"OracleProxy");
    internal static string Exe => Path.Combine(Root,"OracleProxy.Service.exe");
    internal static string Core => Path.Combine(Root,"OracleProxy.Core.exe");
    internal static string Guard => Path.Combine(Root,"OracleProxy.Guard.dll");
    internal static bool IsSystem => WindowsIdentity.GetCurrent().User?.IsWellKnown(WellKnownSidType.LocalSystemSid)==true && Process.GetCurrentProcess().SessionId==0;
    internal static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    internal static void NoLinks(string path)
    {
        for(var p=new DirectoryInfo(Path.GetFullPath(path));p is not null;p=p.Parent)
            if(p.Exists && p.Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");
    }
    internal static void Protect(string path,bool readable)
    {
        NoLinks(path);var security=new DirectorySecurity();
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        security.SetOwner(admin);security.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{system,admin})security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        if(readable)security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);VerifyProtected(path);
    }
    internal static void VerifyProtected(string path)
    {
        NoLinks(path);var acl=new DirectoryInfo(path).GetAccessControl();
        if((acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value is not ("S-1-5-18" or "S-1-5-32-544"))throw new IOException("UNTRUSTED_DIRECTORY_OWNER");
        if(!acl.AreAccessRulesProtected)throw new IOException("UNPROTECTED_DIRECTORY");
        foreach(FileSystemAccessRule r in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(r.AccessControlType==AccessControlType.Allow && r.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
               (r.FileSystemRights & (FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)
                throw new IOException("UNTRUSTED_DIRECTORY_WRITER");
    }
    internal static bool Pinned(string path,string expected)
    {
        if(expected.Length!=64 || !expected.All(Uri.IsHexDigit))return false;
        NoLinks(Path.GetDirectoryName(path)!);
        if(new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))return false;
        using var input=File.OpenRead(path);return CryptographicOperations.FixedTimeEquals(SHA256.HashData(input),Convert.FromHexString(expected));
    }
    internal static void VerifyBundle(string root)
    {
        if(!Pinned(Path.Combine(root,"OracleProxy.Core.exe"),BuildPins.Core) || !Pinned(Path.Combine(root,"OracleProxy.Guard.dll"),BuildPins.Guard))
            throw new IOException("BUNDLE_INTEGRITY_FAILED");
    }
    internal static void WriteAtomic(string path,byte[] content)
    {
        NoLinks(Path.GetDirectoryName(path)!);var pending=path+".pending";
        if(File.Exists(pending) && new FileInfo(pending).Attributes.HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");
        using(var f=new FileStream(pending,FileMode.Create,FileAccess.Write,FileShare.None)){f.Write(content);f.Flush(true);}
        File.Move(pending,path,true);
    }
    internal static void RecordFailure(string stage,Exception error)
    {
        try{
            VerifyProtected(Root);
            string code=error.Message.Length<=80 && error.Message.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')?error.Message:error.HResult.ToString("X8");
            WriteAtomic(Path.Combine(Root,"diagnostics.json"),JsonSerializer.SerializeToUtf8Bytes(new{schema=1,stage,code,category=error.GetType().Name,at=DateTimeOffset.UtcNow.ToUnixTimeSeconds()}));
        }catch{}
    }
    internal static int FixedCommand(string exe,params string[] arguments)
    {
        var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),exe)){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var a in arguments)info.ArgumentList.Add(a);
        using var process=Process.Start(info) ?? throw new IOException("SYSTEM_OPERATION_FAILED");
        process.BeginOutputReadLine();process.BeginErrorReadLine();
        if(!process.WaitForExit(30000)){process.Kill();throw new IOException("SYSTEM_OPERATION_TIMEOUT");}return process.ExitCode;
    }
}
internal sealed class DurableState
{
    public string PrivateKey {get;set;}="";
    public string PublicKey {get;set;}="";
    public string Token {get;set;}="";
    public bool ConnectIntent {get;set;}
    public bool RecoveryRequired {get;set;}
    public string[] UuPaths {get;set;}=[];
    internal static DurableState Load()
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        string path=Path.Combine(Platform.StateRoot,"state.dpapi");if(!File.Exists(path))return new();
        var plain=ProtectedData.Unprotect(File.ReadAllBytes(path),null,DataProtectionScope.CurrentUser);
        try{return JsonSerializer.Deserialize<DurableState>(plain) ?? throw new IOException("STATE_CORRUPT");}
        finally{CryptographicOperations.ZeroMemory(plain);}
    }
    internal void Save()
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        var plain=JsonSerializer.SerializeToUtf8Bytes(this);
        try{Platform.WriteAtomic(Path.Combine(Platform.StateRoot,"state.dpapi"),ProtectedData.Protect(plain,null,DataProtectionScope.CurrentUser));}
        finally{CryptographicOperations.ZeroMemory(plain);}
    }
}
