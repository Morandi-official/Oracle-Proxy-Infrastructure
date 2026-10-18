using System.Diagnostics;
using System.Security.Principal;

namespace OracleProxy.WgAlpha;

// Excluded at the compiler file-list level from every distributable GUI.
// This CI-only harness may create ONE exact-owned native Windows service on
// a disposable GitHub-hosted Windows runner. It never runs on user PCs.
internal static class CiEmbeddedServiceTrial
{
    internal static int Run(string config)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows" ||
            Environment.GetEnvironmentVariable("GITHUB_HEAD_REF") !=
                "test/r113-embedded-service-live-disposable-ci-20261018" ||
            Environment.GetEnvironmentVariable("ORACLE_R113_EXPLICIT_CI") != "CI_ONLY" ||
            !AlphaPreflight.Administrator() ||
            !Path.IsPathFullyQualified(config) ||
            !string.Equals(Path.GetDirectoryName(Path.GetFullPath(config)),
                Environment.GetEnvironmentVariable("RUNNER_TEMP"),
                StringComparison.OrdinalIgnoreCase) ||
            AlphaPreflight.CheckFile(config) != "CONFIG_SHAPE_OK_NOT_NETWORK_PROOF" ||
            EmbeddedWireGuardBridge.ReadServiceState() != "Absent")
            return 3;

        bool attempted = false;
        string started = "NOT_TESTED";
        string removed = "NOT_TESTED";
        try
        {
            attempted = true;
            started = EmbeddedWireGuardBridge.Install(config);
            if (started != "OFFICIAL_WIREGUARD_COMMAND_OK" ||
                EmbeddedWireGuardBridge.ReadServiceState() != "Running")
            {
                Console.WriteLine("R113_NATIVE_OWNED_SERVICE_START_NOT_VERIFIED_DENY");
                return 6;
            }
            // Both signed kernel-driver and live SCM lifecycle observed here;
            // this is NOT a peer handshake, packet safety or Internet proof.
            Console.WriteLine("R113_REAL_LOCAL_WINDOWS_NATIVE_SCM_TUNNEL_RUNNING");
            Thread.Sleep(3000);
            return 0;
        }
        finally
        {
            if (attempted)
            {
                removed = EmbeddedWireGuardBridge.Uninstall();
                if (removed == "OFFICIAL_WIREGUARD_COMMAND_OK" &&
                    EmbeddedWireGuardBridge.ReadServiceState() == "Absent")
                    Console.WriteLine("R113_OWNED_NATIVE_SERVICE_STOP_AND_EXACT_CLEANUP_PASS");
                else
                {
                    Console.WriteLine("R113_OWNED_NATIVE_SERVICE_CLEANUP_UNVERIFIED_DENY");
                    // If the Windows SCM ever fails to stop, the surrounding
                    // disposable CI runner MUST refuse success and be discarded.
                    Environment.ExitCode = 8;
                }
            }
        }
    }
}
