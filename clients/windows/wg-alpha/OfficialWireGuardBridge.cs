using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace OracleProxy.WgAlpha;

// R111: official user-installed WireGuard is the ONLY service controller.
// No bundled driver, arbitrary service names, shell, WFP filters, route edits
// or automatic privilege elevation. Never print process output or config keys.
internal static class OfficialWireGuardBridge
{
    private const uint ScManagerConnect=0x0001;
    private const uint ServiceQueryStatus=0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess {
        public uint ServiceType,CurrentState,ControlsAccepted,Win32ExitCode,
            ServiceSpecificExitCode,CheckPoint,WaitHint,ProcessId,ServiceFlags;
    }

    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr OpenService(IntPtr scm,string service,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service,int level,
        out ServiceStatusProcess status,uint size,out uint needed);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct WinTrustFileInfo {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct WinTrustData {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData,pSIPClientData;
        public uint dwUIChoice,fdwRevocationChecks,dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData,pwszURLReference;
        public uint dwProvFlags,dwUIContext;
        public IntPtr pSignatureSettings;
    }

    // Windows WinVerifyTrust authenticode provider; only trusted, file-bound
    // signatures are accepted. Offline cache-only URL retrieval; never use a
    // publisher name/string or OS file VersionInfo alone as signature proof.
    private static readonly Guid WintrustActionGenericVerifyV2 =
        new("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true,PreserveSig=true)]
    private static extern int WinVerifyTrust(IntPtr hWnd,ref Guid action,
        ref WinTrustData data);

    internal static string InstalledExe =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     "WireGuard","wireguard.exe");

    private static bool VerifyOfficialExecutable()
    {
        if(!OperatingSystem.IsWindows()) return false;
        string path=InstalledExe;
        try {
            var file=new FileInfo(path);
            if(!file.Exists || file.Length<65536 || file.Length>250_000_000 ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Directory is null ||
                file.Directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return false;
            var fi=new WinTrustFileInfo {
                cbStruct=(uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath=path,hFile=IntPtr.Zero,pgKnownSubject=IntPtr.Zero
            };
            IntPtr info=Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            try {
                Marshal.StructureToPtr(fi,info,false);
                var data=new WinTrustData {
                    cbStruct=(uint)Marshal.SizeOf<WinTrustData>(),
                    dwUIChoice=2, // WTD_UI_NONE
                    fdwRevocationChecks=0, // Offline verification is not revocation proof
                    dwUnionChoice=1, // WTD_CHOICE_FILE
                    pFile=info,
                    dwStateAction=0, // WTD_STATEACTION_IGNORE
                    dwProvFlags=0x1000 // WTD_CACHE_ONLY_URL_RETRIEVAL
                };
                Guid action=WintrustActionGenericVerifyV2;
                if(WinVerifyTrust(IntPtr.Zero,ref action,ref data)!=0)
                    return false;
            }
            finally {
                Marshal.DestroyStructure<WinTrustFileInfo>(info);
                Marshal.FreeHGlobal(info);
            }
            using var signer=new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            // A valid Authenticode chain alone is not a vendor identity.
            // Require the upstream publisher as a second independent check.
            return signer.Subject.Contains("O=WireGuard LLC",
                StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    internal static string TrustStatus() =>
        VerifyOfficialExecutable() ?
            "OFFICIAL_INSTALLED_EXE_WINDOWS_AUTHENTICODE_VALID_CACHE_ONLY" :
            "NOT_TRUSTED_OR_NOT_INSTALLED";

    internal static string ReadServiceState()
    {
        if(!OperatingSystem.IsWindows())return "Unknown";
        IntPtr manager=OpenSCManager(null,null,ScManagerConnect);
        if(manager==IntPtr.Zero)return "Unknown";
        try {
            IntPtr handle=OpenService(manager,AlphaPreflight.FixedService,
                ServiceQueryStatus);
            if(handle==IntPtr.Zero)return Marshal.GetLastWin32Error()==1060 ?
                "Absent" : "Unknown";
            try {
                if(!QueryServiceStatusEx(handle,0,out var status,
                    (uint)Marshal.SizeOf<ServiceStatusProcess>(),out _))
                    return "Unknown";
                return status.CurrentState switch {
                    1=>"Stopped",2=>"StartPending",3=>"StopPending",
                    4=>"Running",_=>"Unknown"
                };
            }
            finally { CloseServiceHandle(handle); }
        }
        finally { CloseServiceHandle(manager); }
    }

    internal static string Install(string config)
    {
        if(!AlphaPreflight.Administrator() ||
           !AlphaPreflight.SafeName(config) ||
           AlphaPreflight.CheckFile(config)!="CONFIG_SHAPE_OK_NOT_NETWORK_PROOF" ||
           ReadServiceState()!="Absent")
            return "REFUSED_UNSAFE_START_PRECONDITION";
        return ExecuteFixedCommand("/installtunnelservice",config);
    }

    internal static string Uninstall()
    {
        if(!AlphaPreflight.Administrator())return "REFUSED_NOT_ADMIN";
        // Caller GUI must separately ensure session-local ownership.
        return ExecuteFixedCommand("/uninstalltunnelservice",AlphaPreflight.FixedName);
    }

    private static string ExecuteFixedCommand(string op,string arg)
    {
        if(op is not ("/installtunnelservice" or "/uninstalltunnelservice") ||
            !VerifyOfficialExecutable())return "REFUSED_UNTRUSTED_WIREGUARD_BINARY";
        try {
            var psi=new ProcessStartInfo {
                FileName=InstalledExe,
                UseShellExecute=false,CreateNoWindow=true,
                WindowStyle=ProcessWindowStyle.Hidden,
                WorkingDirectory=Path.GetDirectoryName(InstalledExe)!
            };
            psi.ArgumentList.Add(op);
            psi.ArgumentList.Add(arg);
            using var process=Process.Start(psi);
            if(process is null)return "OFFICIAL_PROCESS_FAILED";
            if(!process.WaitForExit(45000))
                return "OFFICIAL_COMMAND_TIMEOUT_OWNERSHIP_UNKNOWN";
            return process.ExitCode==0 ? "OFFICIAL_WIREGUARD_COMMAND_OK" :
                "OFFICIAL_COMMAND_NONZERO_MAY_HAVE_PARTIAL_SERVICE";
        }
        catch(Win32Exception) { return "OFFICIAL_PROCESS_WIN32_ERROR"; }
        catch { return "OFFICIAL_PROCESS_EXCEPTION"; }
    }

    internal static bool SelfTest()
    {
        // Never touches the installed WireGuard program, services or network.
        return AlphaPreflight.FixedService ==
                "WireGuardTunnel$OracleProxyAlphaTest"
            && AlphaPreflight.FixedName=="OracleProxyAlphaTest"
            && !string.IsNullOrWhiteSpace(InstalledExe)
            && Path.GetFileName(InstalledExe)=="wireguard.exe";
    }
}
