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
#if ENABLE_CI_SEALED_CONFIG
        if (args.Length == 2 && args[0] == "--ci-seal-config")
            return CiSealedConfig.SealOnDisposableRunner(args[1]);
        if (args.Length == 2 && args[0] == "--ci-sealed-wireguard-service")
            return CiSealedConfig.InvokeFromSystemService(args[1]);
#endif
        // R78: CI-only, read-only candidate policy review. Never invoke
        // WireGuardTunnelService, native DLL loading or SCM controls.
        if (args.Length == 1 && args[0] == "--ci-r78-field-scope-self-test")
            return FieldCandidateScopeReview.SelfTest();
        if (args.Length == 1 && args[0] == "--ci-r78-field-scope-review")
            return FieldCandidateScopeReview.ReviewOwnedStagedFile();

        // R79 offline trust gate: never start native service from this path.
        if (args.Length == 1 && args[0] == "--ci-r79-native-bundle-review")
            return NativeBundleReadOnlyReview.Audit();

        // R80: tests use exactly the same strict scope guard that the
        // real LocalSystem native service now invokes before LoadLibrary.
        if (args.Length == 1 && args[0] == "--ci-r80-scope-self-test")
            return NativeLabInnerScopeGate.SelfTest();
        if (args.Length == 1 && args[0] == "--ci-r80-owned-scope-review")
            return NativeLabInnerScopeGate.TestCiOwnedFiles();

#if ENABLE_ATTENDED_FIELD_TRIAL
        // Offline/CI test commands for the separately compiled field
        // diagnostic build. Neither of these can start a service.
        if (args.Length == 1 && args[0] == "--ci-r81-field-self-test")
            return FieldTrialRuntimeLease.SelfTest();
        if (args.Length == 1 && args[0] == "--ci-r81-field-readonly-review")
            return FieldTrialRuntimeLease.CiReview();
#endif

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
