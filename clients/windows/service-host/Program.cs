using System;
using System.Diagnostics;
using System.Security.Principal;

namespace OracleProxy.WireGuardHost;

// Intentionally not a self-installing Windows service.
// Only a separately reviewed SCM registration can launch the real DLL export.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--service-status")
        {
            Console.WriteLine(LabServiceStatus.SanitizedJson());
            return 0;
        }

        if (args.Length == 2 && args[0] == "--signed-driver-ci-self-test")
        {
            if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
                return 3;
            return NativeDriverTrustSelfTests.Run(args[1]) ? 0 : 1;
        }

        if (args.Length == 1 && args[0] == "--self-test")
            return BundleSelfTests.Run() ? 0 : 1;

        if (args.Length is < 1 or > 2 || args[0] != "--wireguard-service")
            return 2;
        string labProfile = args.Length == 2 ? args[1] : "lab-only";
        if (!EngineBundle.IsAllowedLabProfile(labProfile))
            return 2;

        // No elevated action is ever possible through the preview UI or a
        // PowerShell script. The runtime must be in the service session as SYSTEM.
        if (!OperatingSystem.IsWindows())
            return 3;

        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                return 3;
            return OfficialTunnelBridge.InvokeFromService(labProfile);
        }
        catch
        {
            // Do not log exceptions: native errors may expose config file paths.
            return 3;
        }
    }
}
