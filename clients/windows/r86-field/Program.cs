using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;

namespace OracleProxy.R86.NoNetworkMock;

// No networking code, native WireGuard DLLs, routes, WFP or DNS functionality.
// This fixed-name, stop-capable SCM-only service is NOT a VPN.
internal sealed class NoNetworkMock : ServiceBase
{
    internal const string Name = "OracleProxyR86NoNetworkMock";
    internal NoNetworkMock()
    {
        ServiceName = Name;
        CanStop = true;
        CanShutdown = true;
        CanPauseAndContinue = false;
        AutoLog = false;
    }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
}
internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1 ||
            args[0] != "--r86-no-network-mock") return 2;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0) return 3;
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "OracleProxyR86Attended");
            string marker = Path.Combine(root, "owner.txt");
            if (!File.Exists(marker) ||
                (File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0 ||
                File.ReadAllText(marker).Trim() != "R86-ATTENDED-OWNED-NO-NETWORK-ONLY")
                return 3;
            ServiceBase.Run(new NoNetworkMock());
            return 0;
        }
        catch { return 3; }
    }
}
