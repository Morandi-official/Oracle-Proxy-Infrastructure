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

        bool startVerified = false;
        bool cleanupVerified = false;
        try
        {
            string started = EmbeddedWireGuardBridge.Install(config);
            startVerified = started == "OFFICIAL_WIREGUARD_COMMAND_OK" &&
                EmbeddedWireGuardBridge.ReadServiceState() == "Running";
            if (startVerified)
            {
                Console.WriteLine("R113_REAL_LOCAL_WINDOWS_NATIVE_SCM_TUNNEL_RUNNING");
                // A running service proves neither peer handshake nor WAN.
                Thread.Sleep(3000);
            }
            else Console.WriteLine("R113_NATIVE_OWNED_SERVICE_START_NOT_VERIFIED_DENY");
        }
        finally
        {
            // Always attempt exact-owned removal, even after a failed start.
            string removed = EmbeddedWireGuardBridge.Uninstall();
            cleanupVerified = removed == "OFFICIAL_WIREGUARD_COMMAND_OK" &&
                EmbeddedWireGuardBridge.ReadServiceState() == "Absent";
            Console.WriteLine(cleanupVerified
                ? "R113_OWNED_NATIVE_SERVICE_STOP_AND_EXACT_CLEANUP_PASS"
                : "R113_OWNED_NATIVE_SERVICE_CLEANUP_UNVERIFIED_DENY");
        }
        return startVerified && cleanupVerified ? 0 : 8;
    }
}
