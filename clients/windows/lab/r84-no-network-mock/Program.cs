using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;

namespace OracleProxy.R84.NoNetworkMock;

// Test-only WINDOWS SCM service. It owns NO tunnel, driver, socket, routes,
// firewall or DNS. ServiceName deliberately matches prospective lab-field
// so a CI-only SYSTEM scheduled watcher can be validated on exact ownership.
internal sealed class Mock : ServiceBase
{
    public Mock()
    {
        ServiceName = "WireGuardTunnel$lab-field";
        CanStop = true;
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
            args[0] != "--ci-r84-no-network-service") return 2;
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            if (!id.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                return 3;
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "OracleProxyLab");
            string marker = Path.Combine(root, ".r81-owned");
            if (!File.Exists(marker) ||
                (File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0 ||
                File.ReadAllText(marker).Trim() !=
                    "CI_R81_ONLY_DISPOSABLE_GITHUB_VM") return 3;
            ServiceBase.Run(new Mock());
            return 0;
        }
        catch { return 3; }
    }
}
