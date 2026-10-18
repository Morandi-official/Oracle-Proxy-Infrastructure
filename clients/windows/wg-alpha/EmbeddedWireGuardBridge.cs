using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using OracleProxy.WireGuardHost;

namespace OracleProxy.WgAlpha;

// R112 independently packaged engine: no wireguard.exe, no official GUI/MSI.
// This is an unsigned, physically attended Alpha, never the R83 production
// kernel. The only native service name, executable path and config are fixed.
internal static class EmbeddedWireGuardBridge
{
    private const string Executable = "OracleProxy.WgAlpha.exe";
    private const string TunnelDll = "tunnel.dll";
    private const string DriverDll = "wireguard.dll";
    private const string ServiceArg = "--service";
    // Replaced with a verified 64-digit hex digest by one exact GitHub CI
    // job AFTER compiling upstream and BEFORE compiling this C# binary.
    internal const string PinnedTunnelSha256 = "R112_BUILDER_MUST_EMBED_TUNNEL_SHA256";
    private static string InstallRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "OracleProxyEmbeddedAlpha");
    private static string ConfigRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "OracleProxyEmbeddedAlpha");
    private static string StagedConfig => Path.Combine(ConfigRoot, AlphaPreflight.FixedName + ".conf");
    private static string ServiceExecutable => Path.Combine(InstallRoot, Executable);
    private static string ExpectedImage => "\"" + ServiceExecutable + "\" " + ServiceArg;

    private const uint ScManagerConnect=0x1, ScManagerCreate=0x2;
    private const uint ServiceQuery=0x4, ServiceStop=0x20, ServiceStart=0x10;
    private const uint ServiceAllAccess=0xF01FF;
    private const uint ServiceWin32OwnProcess=0x10, ServiceDemandStart=3, ServiceErrorNormal=1;
    private const uint DeleteAccess=0x10000, SidUnrestricted=1;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode;
        public uint ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceSidInfo { public uint ServiceSidType; }

    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr OpenScManager(string? machine,string? database,uint desired);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr OpenService(IntPtr manager,string name,uint desired);
    [DllImport("advapi32.dll",EntryPoint="CreateServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr CreateService(IntPtr manager,string name,string display,
        uint access,uint type,uint startType,uint errorControl,string image,
        string? group,IntPtr tag,string? dependencies,string? account,string? password);
    [DllImport("advapi32.dll",EntryPoint="ChangeServiceConfig2W",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(IntPtr service,uint infoLevel,
        ref ServiceSidInfo info);
    [DllImport("advapi32.dll",EntryPoint="StartServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(IntPtr service,uint argc,IntPtr argv);
    [DllImport("advapi32.dll",EntryPoint="ControlService",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr service,uint control,out ServiceStatus status);
    [DllImport("advapi32.dll",EntryPoint="QueryServiceStatusEx",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service,int info,
        out ServiceStatus status,uint bytes,out uint required);
    [DllImport("advapi32.dll",EntryPoint="DeleteService",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr LoadLibraryEx(string path,IntPtr handle,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern bool FreeLibrary(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private delegate bool NativeService([MarshalAs(UnmanagedType.LPWStr)]string configuration);

    private static bool Pinned(string path,string sha256)
    {
        if (sha256.Length!=64 ||
            !sha256.All(c=>Uri.IsHexDigit(c)))return false;
        try {
            var file=new FileInfo(path);
            if(!file.Exists || file.Length is < 1024 or > 20_000_000 ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint))return false;
            using var f=File.OpenRead(path);
            var digest=SHA256.HashData(f);
            return CryptographicOperations.FixedTimeEquals(digest,Convert.FromHexString(sha256));
        } catch { return false; }
    }

    private static bool TrustedBundle(string root)
    {
        if (!Directory.Exists(root)) return false;
        var folder=new DirectoryInfo(root);
        if (folder.Attributes.HasFlag(FileAttributes.ReparsePoint))return false;
        return Pinned(Path.Combine(root,TunnelDll),PinnedTunnelSha256) &&
               NativeDriverTrust.IsPinnedOfficialDriver(Path.Combine(root,DriverDll)) &&
               NativeDriverTrust.IsTrustedLocalSignature(Path.Combine(root,DriverDll));
    }

    internal static string TrustStatus() =>
        TrustedBundle(AppContext.BaseDirectory) ?
        "PINNED_SOURCE_BUILT_TUNNEL_AND_SIGNED_OFFICIAL_WGNT" :
        "ENGINE_NOT_PINNED_OR_NOT_VERIFIABLE";

    private static bool HasProtectedAcl(string path,bool isDirectory)
    {
        try {
            FileSystemSecurity acl=isDirectory ?
                (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(
                    AccessControlSections.Owner|AccessControlSections.Access) :
                new FileInfo(path).GetAccessControl(
                    AccessControlSections.Owner|AccessControlSections.Access);
            if(!acl.AreAccessRulesProtected)return false;
            string? owner=(acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
            if(owner is not ("S-1-5-18" or "S-1-5-32-544"))return false;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                if(rule.AccessControlType!=AccessControlType.Allow)continue;
                if(rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                    return false;
            }
            return true;
        } catch{return false;}
    }
    private static void Protect(string path,bool directory)
    {
        SecurityIdentifier admin=new(WellKnownSidType.BuiltinAdministratorsSid,null);
        SecurityIdentifier system=new(WellKnownSidType.LocalSystemSid,null);
        if(directory) {
            var acl=new DirectorySecurity();
            acl.SetOwner(admin);
            acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[]{admin,system})
                acl.AddAccessRule(new FileSystemAccessRule(sid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(acl);
        } else {
            var acl=new FileSecurity();
            acl.SetOwner(admin); acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[]{admin,system})
                acl.AddAccessRule(new FileSystemAccessRule(sid,
                    FileSystemRights.FullControl,AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
        }
        if(!HasProtectedAcl(path,directory))throw new IOException("ACL_NOT_PROTECTED");
    }

    internal static string ReadServiceState()
    {
        if(!OperatingSystem.IsWindows())return "Unknown";
        IntPtr scm=OpenScManager(null,null,ScManagerConnect);
        if(scm==IntPtr.Zero)return "Unknown";
        try{
            IntPtr svc=OpenService(scm,AlphaPreflight.FixedService,ServiceQuery);
            if(svc==IntPtr.Zero)return Marshal.GetLastWin32Error()==1060?"Absent":"Unknown";
            try{
                if(!QueryServiceStatusEx(svc,0,out var status,
                    (uint)Marshal.SizeOf<ServiceStatus>(),out _))return "Unknown";
                return status.CurrentState switch {
                    1=>"Stopped",2=>"StartPending",3=>"StopPending",4=>"Running",_=>"Unknown"
                };
            } finally {CloseServiceHandle(svc);}
        } finally{CloseServiceHandle(scm);}
    }

    // No pre-existing install directory may be adopted, and nothing is
    // removed on partial failure. The operator needs physical recovery.
    internal static string Install(string config)
    {
        if(!OperatingSystem.IsWindows() || !AlphaPreflight.Administrator() ||
           !AlphaPreflight.SafeName(config) ||
           AlphaPreflight.CheckFile(config)!="CONFIG_SHAPE_OK_NOT_NETWORK_PROOF" ||
           ReadServiceState()!="Absent" ||
           Directory.Exists(InstallRoot) || Directory.Exists(ConfigRoot) ||
           !TrustedBundle(AppContext.BaseDirectory))
            return "REFUSED_EMBEDDED_START_PRECONDITION";
        bool registered=false;
        try {
            Directory.CreateDirectory(InstallRoot);
            Protect(InstallRoot,true);
            Directory.CreateDirectory(ConfigRoot);
            Protect(ConfigRoot,true);
            foreach(string name in new[]{Executable,TunnelDll,DriverDll}) {
                string source=Path.Combine(AppContext.BaseDirectory,name);
                string dest=Path.Combine(InstallRoot,name);
                var info=new FileInfo(source);
                if(!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new IOException("BAD_SOURCE_FILE");
                File.Copy(source,dest,false);
                Protect(dest,false);
                using var input=File.OpenRead(source);
                using var output=File.OpenRead(dest);
                if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(input),SHA256.HashData(output)))
                    throw new IOException("STAGING_INTEGRITY_ERROR");
            }
            File.Copy(config,StagedConfig,false);
            Protect(StagedConfig,false);
            if(!TrustedBundle(InstallRoot) ||
                !HasProtectedAcl(InstallRoot,true) ||
                !HasProtectedAcl(ConfigRoot,true) ||
                !HasProtectedAcl(StagedConfig,false))
                throw new IOException("STAGING_TRUST_NOT_VERIFIED");
            IntPtr scm=OpenScManager(null,null,ScManagerConnect|ScManagerCreate);
            if(scm==IntPtr.Zero)throw new IOException("SCM_NOT_AVAILABLE");
            try {
                IntPtr service=CreateService(scm,AlphaPreflight.FixedService,
                    "Oracle Proxy Embedded Alpha Test Tunnel",ServiceAllAccess,
                    ServiceWin32OwnProcess,ServiceDemandStart,ServiceErrorNormal,
                    ExpectedImage,null,IntPtr.Zero,"Nsi\0TcpIp\0\0",
                    "LocalSystem",null);
                if(service==IntPtr.Zero)throw new IOException("SCM_REGISTER_FAILED");
                registered=true;
                try {
                    var sid=new ServiceSidInfo{ServiceSidType=SidUnrestricted};
                    if(!ChangeServiceConfig2(service,5,ref sid))
                        throw new IOException("SCM_SERVICE_SID_FAILED");
                    if(!StartService(service,0,IntPtr.Zero))
                        throw new IOException("SCM_SERVICE_START_FAILED");
                } finally {CloseServiceHandle(service);}
            } finally {CloseServiceHandle(scm);}
            for(int i=0;i<20;i++) {
                if(ReadServiceState()=="Running")
                    return "OFFICIAL_WIREGUARD_COMMAND_OK";
                Thread.Sleep(500);
            }
            return "EMBEDDED_SERVICE_NOT_RUNNING_UNVERIFIED";
        } catch {
            return registered?"EMBEDDED_PARTIAL_SERVICE_REQUIRES_ATTENDED_RECOVERY":
                "EMBEDDED_STAGE_FAILED_REQUIRES_LOCAL_INSPECTION";
        }
    }

    private static bool ExactOwnedServiceImage()
    {
        try {
            using var key=Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\"+AlphaPreflight.FixedService);
            return string.Equals(key?.GetValue("ImagePath") as string,
                ExpectedImage,StringComparison.OrdinalIgnoreCase);
        }catch{return false;}
    }

    internal static string Uninstall()
    {
        if(!AlphaPreflight.Administrator() || !ExactOwnedServiceImage())
            return "REFUSED_SERVICE_NOT_OWNED";
        IntPtr scm=OpenScManager(null,null,ScManagerConnect);
        if(scm==IntPtr.Zero)return "SCM_UNAVAILABLE";
        try{
            IntPtr service=OpenService(scm,AlphaPreflight.FixedService,
                ServiceQuery|ServiceStop|DeleteAccess);
            if(service==IntPtr.Zero)return "SCM_NOT_OWNED";
            try{
                if(ReadServiceState()=="Running") {
                    if(!ControlService(service,1,out _))
                        return "SCM_STOP_FAILED_REQUIRES_LOCAL_RECOVERY";
                }
                for(int i=0;i<30;i++){
                    if(ReadServiceState()=="Stopped")break;
                    Thread.Sleep(500);
                }
                if(ReadServiceState()!="Stopped")
                    return "SCM_STOP_TIMEOUT_REQUIRES_LOCAL_RECOVERY";
                if(!DeleteService(service))
                    return "SCM_DELETE_FAILED_REQUIRES_LOCAL_RECOVERY";
            } finally {CloseServiceHandle(service);}
        }finally {CloseServiceHandle(scm);}
        for(int i=0;i<30;i++){
            if(ReadServiceState()=="Absent") {
                // Delete only this session's exactly staged, pinned files,
                // provided no foreign files or untrusted ACLs were added.
                try {
                    if(!HasProtectedAcl(InstallRoot,true) ||
                       !HasProtectedAcl(ConfigRoot,true) ||
                       !TrustedBundle(InstallRoot) ||
                       !HasProtectedAcl(StagedConfig,false))
                        return "SCM_REMOVED_BUT_STAGING_TRUST_UNKNOWN";
                    var binaries=Directory.GetFiles(InstallRoot)
                        .Select(Path.GetFileName).OrderBy(x=>x).ToArray();
                    var expected=new[]{Executable,TunnelDll,DriverDll}.OrderBy(x=>x).ToArray();
                    if(!binaries.SequenceEqual(expected,StringComparer.OrdinalIgnoreCase) ||
                       Directory.GetFiles(ConfigRoot).Length!=1 ||
                       Directory.GetDirectories(InstallRoot).Length!=0 ||
                       Directory.GetDirectories(ConfigRoot).Length!=0)
                        return "SCM_REMOVED_BUT_STAGING_NOT_EXACT";
                    foreach(string name in expected)
                        File.Delete(Path.Combine(InstallRoot,name));
                    File.Delete(StagedConfig);
                    Directory.Delete(InstallRoot,false);
                    Directory.Delete(ConfigRoot,false);
                } catch {
                    return "SCM_REMOVED_BUT_STAGING_REQUIRES_MANUAL_CLEANUP";
                }
                return "OFFICIAL_WIREGUARD_COMMAND_OK";
            }
            Thread.Sleep(500);
        }
        return "SCM_DELETE_PENDING_REQUIRES_LOCAL_INSPECTION";
    }

    internal static int RunWindowsService()
    {
        if(!OperatingSystem.IsWindows())return 3;
        try{
            using var id=WindowsIdentity.GetCurrent();
            if(!id.IsSystem || Process.GetCurrentProcess().SessionId!=0 ||
               !string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\'),
                    InstallRoot,StringComparison.OrdinalIgnoreCase) ||
               !ExactOwnedServiceImage() ||
               !HasProtectedAcl(InstallRoot,true) ||
               !HasProtectedAcl(ConfigRoot,true) ||
               !HasProtectedAcl(StagedConfig,false) ||
               !TrustedBundle(InstallRoot) ||
               AlphaPreflight.CheckFile(StagedConfig)!="CONFIG_SHAPE_OK_NOT_NETWORK_PROOF")
                return 3;
            IntPtr module=LoadLibraryEx(Path.Combine(InstallRoot,TunnelDll),
                IntPtr.Zero,0x100|0x1000);
            if(module==IntPtr.Zero)return 3;
            try{
                IntPtr export=NativeLibrary.GetExport(module,"WireGuardTunnelService");
                var service=Marshal.GetDelegateForFunctionPointer<NativeService>(export);
                return service(StagedConfig)?0:3;
            }finally{FreeLibrary(module);}
        }catch{return 3;}
    }

    internal static bool SelfTest()
    {
        // No Admin, WFP, SCM, DLL call or network mutation on the runner.
        return AlphaPreflight.FixedService=="WireGuardTunnel$OracleProxyAlphaTest" &&
            ExpectedImage.Contains("OracleProxy.WgAlpha.exe",StringComparison.Ordinal) &&
            !ExpectedImage.Contains("wireguard.exe",StringComparison.OrdinalIgnoreCase) &&
            PinnedTunnelSha256.Length==64 &&
            PinnedTunnelSha256.All(Uri.IsHexDigit) &&
            ServiceArg=="--service";
    }
}
