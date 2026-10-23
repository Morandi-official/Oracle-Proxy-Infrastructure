#if ENABLE_DISPOSABLE_LAB_CONTROLS
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace OracleProxy.LabManager;

// R50: explicitly authorized, one-use, disposable SYSTEM-only WFP release.
// Separate from normal manager start, never wired to GUI, IPC or production.
// No adapter, firewall profile, route or third-party service may be removed.
internal sealed class CiSystemOwnedWfpReleaseService : ServiceBase
{
    internal const string FixedName = "OracleProxyLabWfpRelease";
    private const string Approved = "R50_CI_RELEASE_ONLY";

    internal CiSystemOwnedWfpReleaseService()
    {
        ServiceName = FixedName;
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = false;
    }

    private static bool FixedProtectedTestStageVerified()
    {
        if (!CiSystemDpapiKeyLease.IsSystemServiceIdentity()) return false;
        try
        {
            string root = CiSystemNativeDpapiBridge.StageRoot;
            var dir = new DirectoryInfo(root);
            if (!dir.Exists || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            foreach (var pair in new[] {
                (".r47-ci-owned", "R47_GITHUB_DISPOSABLE_VM_ONLY"),
                (".r47-result", "PASS"),
                (".r50-release-approved", Approved)
            })
            {
                var file = new FileInfo(Path.Combine(root, pair.Item1));
                if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    file.Length is < 1 or > 96 ||
                    File.ReadAllText(file.FullName).Trim() != pair.Item2)
                    return false;
            }
            if (File.Exists(Path.Combine(root, ".r50-release-result")))
                return false;

            using (var mgr = new ServiceController(LabManagerService.FixedServiceName))
            {
                // An existing but STOPPED manager is expected after native
                // peers finish. Refuse release if manager is still running.
                if (mgr.Status != ServiceControllerStatus.Stopped) return false;
            }
            if (NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                    n.Name is "OracleLabTestA" or "OracleLabTestB"))
                return false;
            if (Process.GetProcesses().Any(p =>
                    p.ProcessName.StartsWith("wgnt-r44-dpapi",
                        StringComparison.OrdinalIgnoreCase)))
                return false;
            return CiSystemFixedTargetWfpGuard.IsActive();
        }
        catch { return false; }
    }

    protected override void OnStart(string[] args)
    {
        if (!FixedProtectedTestStageVerified() ||
            !CiSystemFixedTargetWfpGuard.RemoveExactVerifiedOnly())
            throw new InvalidOperationException("R50 refused unsafe WFP release");

        // One-time receipt is for disposable CI only. OS rule absence is
        // independently rechecked by PowerShell before declaring success.
        string receipt = Path.Combine(CiSystemNativeDpapiBridge.StageRoot,
            ".r50-release-result");
        using var stream = new FileStream(receipt, FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 512, FileOptions.WriteThrough);
        byte[] value = System.Text.Encoding.ASCII.GetBytes("PASS");
        stream.Write(value);
        stream.Flush(true);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);
    }
}
#endif
