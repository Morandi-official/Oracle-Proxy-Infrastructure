#if ENABLE_DISPOSABLE_LAB_CONTROLS
using System.Diagnostics;
using System.Security.Cryptography;

namespace OracleProxy.LabManager;

// R47: bounded disposable-CI bridge from real SYSTEM SCM to R44's native
// in-memory DPAPI/WireGuardNT pair. NEVER included in default distribution.
// No caller-selected paths, peers, addresses or commands.
internal static class CiSystemNativeDpapiBridge
{
    internal static readonly string StageRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "OracleProxyR47CiOnly");
    private const string Approval = "R47_GITHUB_DISPOSABLE_VM_ONLY";
    private static readonly string[] Binaries =
        { "wgnt-r44-dpapi-native.exe", "wireguard.dll", "wg-r44-session.dpapi" };

    internal static bool Preflight()
    {
        if (!CiSystemDpapiKeyLease.IsSystemServiceIdentity()) return false;
        try
        {
            var directory = new DirectoryInfo(StageRoot);
            if (!directory.Exists ||
                (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;

            string markerPath = Path.Combine(StageRoot, ".r47-ci-owned");
            var marker = new FileInfo(markerPath);
            if (!marker.Exists ||
                (marker.Attributes & FileAttributes.ReparsePoint) != 0 ||
                marker.Length is < 8 or > 96 ||
                File.ReadAllText(markerPath).Trim() != Approval)
                return false;
            foreach (string name in Binaries)
            {
                var item = new FileInfo(Path.Combine(StageRoot, name));
                if (!item.Exists ||
                    (item.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    item.Length is < 128 or > 16_000_000)
                    return false;
            }
            return !File.Exists(Path.Combine(StageRoot, ".r47-result"));
        }
        catch { return false; }
    }

    internal static async Task RunAsync(CancellationToken token,
        bool fixedWfpRequired = false)
    {
        bool ok = false;
        Process? child = null;
        try
        {
            if (!Preflight() ||
                (fixedWfpRequired && !CiSystemFixedTargetWfpGuard.IsActive())) return;
            var startup = new ProcessStartInfo
            {
                FileName = Path.Combine(StageRoot, Binaries[0]),
                WorkingDirectory = StageRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startup.ArgumentList.Add(Path.Combine(StageRoot, Binaries[1]));
            startup.ArgumentList.Add(Path.Combine(StageRoot, Binaries[2]));
            // The native executable's environment test is defense in depth;
            // the real trust boundary is this lab-only SYSTEM service binary
            // and an ACL-verified, ephemeral CI stage. Never production.
            startup.Environment["GITHUB_ACTIONS"] = "true";
            startup.Environment["RUNNER_ENVIRONMENT"] = "github-hosted";
            startup.Environment["RUNNER_OS"] = "Windows";
            startup.Environment["ORACLE_R44_DPAPI_TEST"] = "CI_ONLY";

            child = Process.Start(startup);
            if (child is null) return;
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            limit.CancelAfter(TimeSpan.FromSeconds(85));
            await child.WaitForExitAsync(limit.Token);
            ok = child.ExitCode == 0 && !token.IsCancellationRequested &&
                (!fixedWfpRequired || CiSystemFixedTargetWfpGuard.IsActive());
        }
        catch { ok = false; }
        finally
        {
            if (child is not null)
            {
                try
                {
                    if (!child.HasExited) child.Kill(entireProcessTree: true);
                    child.WaitForExit(3000);
                }
                catch { /* OS-owned disposable runner cleanup checks residuals */ }
                child.Dispose();
            }
            // Exactly one SUCCESS/FAIL receipt, never a private key or route.
            // CI checks this from a separate elevated runner process.
            try
            {
                string path = Path.Combine(StageRoot, ".r47-result");
                using var stream = new FileStream(path, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 256, FileOptions.WriteThrough);
                byte[] bytes = System.Text.Encoding.ASCII.GetBytes(ok ? "PASS" : "FAIL");
                try { stream.Write(bytes); stream.Flush(true); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch { /* missing receipt is always test failure */ }
        }
    }
}
#endif
