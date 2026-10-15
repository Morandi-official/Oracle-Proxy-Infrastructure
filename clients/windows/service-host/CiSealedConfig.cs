#if ENABLE_CI_SEALED_CONFIG
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace OracleProxy.WireGuardHost;

// A REAL DPAPI(LocalMachine)->SYSTEM->native WireGuard SCM lab bridge.
// Compiled ONLY for the explicitly authorized disposable R30 Windows runner.
// The upstream tunnel.dll *requires a path*, so temporary plaintext remains
// present while the native service runs. It is NOT a production key vault.
// On hard power loss an orphan may remain; independent CI teardown removes it.
internal static class CiSealedConfig
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("OracleProxy.R30.DisposableSealedConfig.v1.NOT-PRODUCTION");
    private static readonly SecurityIdentifier Admin =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);

    private static string ConfigRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "OracleProxyLab", "config");

    private static bool AuthorizedLabMarker()
    {
        try
        {
            string root = Path.GetDirectoryName(ConfigRoot)!;
            string marker = Path.Combine(root, ".ci-control-approved");
            var file = new FileInfo(marker);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            ConfigAclGate.RequireProtectedLabSealedFile(marker);
            return File.ReadAllText(marker).Trim() == "DISPOSABLE_GITHUB_RUNNER_ONLY";
        }
        catch { return false; }
    }

    private static string CipherPath(string profile)
    {
        if (profile is not ("lab-peer-a" or "lab-peer-b"))
            throw new InvalidOperationException("Only fixed disposable peers");
        return Path.Combine(ConfigRoot, profile + ".conf.dpapi");
    }

    private static FileSecurity SecureFileAcl()
    {
        var acl = new FileSecurity();
        acl.SetOwner(Admin);
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { Admin, System })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                AccessControlType.Allow));
        return acl;
    }

    private static void CreateOwnedFile(string path, ReadOnlySpan<byte> bytes)
    {
        // Only create, never overwrite a pre-existing config or ciphertext.
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
            FileShare.None, 4096, FileOptions.WriteThrough);
        // Parent folder must already be System/Admin-only before CreateNew;
        // never fill this file before its inherited ACL is replaced.
        new FileInfo(path).SetAccessControl(SecureFileAcl());
        stream.Write(bytes);
        stream.Flush(true);
        ConfigAclGate.RequireProtectedLabSealedFile(path);
    }

    internal static int SealOnDisposableRunner(string profile)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("ORACLE_R30_DPAPI_TEST") != "CI_ONLY" ||
            !AuthorizedLabMarker())
            return 3;
        using (var id = WindowsIdentity.GetCurrent())
        {
            if (!id.IsAuthenticated ||
                !new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator))
                return 3;
        }

        byte[]? plain = null;
        byte[]? encrypted = null;
        try
        {
            string path = EngineBundle.FixedConfigPath(profile);
            string sealedPath = CipherPath(profile);
            ConfigAclGate.RequireProtectedLabSealedFile(path);
            if (File.Exists(sealedPath)) return 3;
            var original = new FileInfo(path);
            if (original.Length is < 1 or > 16384) return 3;
            plain = File.ReadAllBytes(path);
            encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);
            if (encrypted.Length is < 1 or > 32768) return 3;
            CreateOwnedFile(sealedPath, encrypted);
            // This deletion is only of the CI job-created source config. A
            // real allocator with no plaintext file is still needed for GA.
            File.Delete(path);
            if (File.Exists(path)) return 3;
            return 0;
        }
        catch { return 3; }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    internal static int InvokeFromSystemService(string profile)
    {
        if (!OperatingSystem.IsWindows() || !AuthorizedLabMarker() ||
            profile is not ("lab-peer-a" or "lab-peer-b"))
            return 3;
        using (var id = WindowsIdentity.GetCurrent())
        {
            if (!id.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                return 3;
        }

        string plainPath = EngineBundle.FixedConfigPath(profile);
        string encryptedPath = CipherPath(profile);
        byte[]? encrypted = null;
        byte[]? plain = null;
        bool ownsPlain = false;
        try
        {
            ConfigAclGate.RequireProtectedLabSealedFile(encryptedPath);
            var cipher = new FileInfo(encryptedPath);
            if (cipher.Length is < 1 or > 32768 || File.Exists(plainPath))
                return 3; // Fail closed on leftover from a previous crash.
            encrypted = File.ReadAllBytes(encryptedPath);
            plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
            if (plain.Length is < 1 or > 16384) return 3;
            // EngineBundle verifies config hash and native binaries AFTER
            // restoration. The independent protected manifest is pinned by
            // the disposable CI job, not a production supply-chain signature.
            ownsPlain = true;
            CreateOwnedFile(plainPath, plain);
            return OfficialTunnelBridge.InvokeFromService(profile);
        }
        catch { return 3; }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted);
            if (ownsPlain)
            {
                try { File.Delete(plainPath); }
                catch { /* isolated runner teardown checks owned cleanup */ }
            }
        }
    }
}
#endif
