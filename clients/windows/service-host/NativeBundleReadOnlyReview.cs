using System;
using System.IO;
using System.Security.Principal;

namespace OracleProxy.WireGuardHost;

// R79: an independent read-only verification of the ACTUAL signed native
// DLL / source-built tunnel.dll / manifest / fixed lab service configuration,
// immediately before the authenticated GUI manager is allowed to start
// CI-only native SCM peers. No LoadLibrary, SCM, WFP, route or DNS operations.
internal static class NativeBundleReadOnlyReview
{
    private static bool ExactCiScope() =>
        OperatingSystem.IsWindows() &&
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
        Environment.GetEnvironmentVariable("RUNNER_OS") == "Windows" &&
        Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted" &&
        Environment.GetEnvironmentVariable("ORACLE_R79") == "CI_ONLY";

    internal static int Audit()
    {
        if (!ExactCiScope()) return 3;
        try
        {
            using WindowsIdentity caller = WindowsIdentity.GetCurrent();
            if (!caller.IsAuthenticated ||
                !new WindowsPrincipal(caller).IsInRole(
                    WindowsBuiltInRole.Administrator))
                return 3;

            string programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrEmpty(programData)) return 3;
            string root = Path.Combine(programData, "OracleProxyLab");
            string marker = Path.Combine(root, ".ci-control-approved");
            ConfigAclGate.RequireProtectedLabSealedFile(marker);
            if (File.ReadAllText(marker).Trim() !=
                "DISPOSABLE_GITHUB_RUNNER_ONLY")
                return 3;

            // Both owned bundles must pass independently. Never choose a
            // profile, DLL, config, manifest or network target from CLI.
            foreach (string profile in new[] { "lab-peer-a", "lab-peer-b" })
            {
                string hostDir = Path.Combine(root, profile);
                string conf = EngineBundle.FixedConfigPath(profile);
                EngineBundle.VerifiedFiles verified =
                    EngineBundle.Verify(hostDir, conf);
                ConfigAclGate.RequireProtectedLabInstallation(
                    hostDir, conf, profile);
                NativeDriverTrust.RequireTrustedPinnedOfficialDriver(
                    verified.WireGuardDll);
            }
            Console.WriteLine("R79_BOTH_OWNED_NATIVE_BUNDLES_SIGNED_PINNED_AND_PROTECTED_PASS");
            Console.WriteLine("R79_NATIVE_ACTIVATION_APPROVED=false");
            return 0;
        }
        catch
        {
            // The error must NEVER contain configuration data, paths, peers,
            // private keys or any other information from privileged files.
            return 3;
        }
    }
}
