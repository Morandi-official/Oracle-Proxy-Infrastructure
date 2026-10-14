using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace OracleProxy.IntentLab;

/// <summary>
/// OFFLINE CI-only proof of encrypted WireGuard 32-byte key material storage.
/// NOT used by the tunnel engine or shipped as a production credential vault.
/// DPAPI LocalMachine alone does not restrict local users: protected NTFS
/// ACLs, service identity and native in-memory key handling are also required.
/// </summary>
internal sealed class PeerSecretStore
{
    private const string FixedFileName = "peer-secret.dpapi";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes(
        "OracleProxy.R17.PeerSecret.v1.not-a-production-profile");
    private static readonly SecurityIdentifier Admin =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);
    private readonly string _folder;
    private readonly string _file;

    internal PeerSecretStore(string directory)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
            throw new InvalidOperationException("R17 offline disposable runner only");
        string root = Environment.GetEnvironmentVariable("RUNNER_TEMP") ??
            throw new InvalidOperationException("No disposable runner root");
        root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
            throw new InvalidOperationException("Unsafe secret directory");
        _folder = Path.GetFullPath(directory);
        if (!_folder.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Secret store outside runner temp");
        _file = Path.Combine(_folder, FixedFileName);
        RequireProtectedFolder();
    }

    private static FileSystemSecurity ProtectedAcl(bool directory)
    {
        FileSystemSecurity acl = directory ? new DirectorySecurity() : new FileSecurity();
        acl.SetOwner(Admin);
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { Admin, System })
        {
            var rule = directory
                ? new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow)
                : new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    AccessControlType.Allow);
            acl.AddAccessRule(rule);
        }
        return acl;
    }

    // CI fixture only. Never changes an existing network configuration.
    internal static void ProtectNewTestFolder(string directory)
    {
        var folder = new DirectoryInfo(directory);
        if (!folder.Exists || (folder.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("R17 test directory unsafe");
        folder.SetAccessControl((DirectorySecurity)ProtectedAcl(true));
    }

    private static void ValidateAcl(FileSystemSecurity acl)
    {
        if (!acl.AreAccessRulesProtected)
            throw new InvalidOperationException("Inherited secret ACL");
        string? owner = (acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
        if (owner is null || (owner != Admin.Value && owner != System.Value))
            throw new InvalidOperationException("Untrusted secret owner");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true,
                     typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Value != Admin.Value &&
                rule.IdentityReference.Value != System.Value)
                throw new InvalidOperationException("Untrusted access to secret");
        }
    }

    private void RequireProtectedFolder()
    {
        var directory = new DirectoryInfo(_folder);
        if (!directory.Exists ||
            (directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Missing or unsafe secret directory");
        ValidateAcl(directory.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access));
    }

    private void RequireProtectedFile()
    {
        RequireProtectedFolder();
        var file = new FileInfo(_file);
        if (!file.Exists ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length is < 1 or > 4096)
            throw new InvalidOperationException("Invalid protected secret file");
        ValidateAcl(file.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access));
    }

    internal void Seal(byte[] rawKey)
    {
        RequireProtectedFolder();
        if (rawKey is null || rawKey.Length != 32 || File.Exists(_file))
            throw new InvalidOperationException("Only a fresh X25519 secret is allowed");
        byte[] copy = (byte[])rawKey.Clone();
        byte[] cipher = Array.Empty<byte>();
        try
        {
            cipher = ProtectedData.Protect(copy, Entropy, DataProtectionScope.LocalMachine);
            if (cipher.Length is < 1 or > 4096)
                throw new InvalidOperationException("Unexpected protected data size");
            using (var fs = new FileStream(_file, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                fs.Write(cipher);
                fs.Flush(flushToDisk: true);
            }
            new FileInfo(_file).SetAccessControl((FileSecurity)ProtectedAcl(false));
            RequireProtectedFile();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    // Caller must zero returned secret immediately after controlled use.
    internal byte[] Open()
    {
        RequireProtectedFile();
        byte[] cipher = File.ReadAllBytes(_file);
        try
        {
            byte[] plain = ProtectedData.Unprotect(cipher, Entropy,
                DataProtectionScope.LocalMachine);
            if (plain.Length == 32) return plain;
            CryptographicOperations.ZeroMemory(plain);
            throw new InvalidOperationException("Unexpected decrypted key length");
        }
        finally { CryptographicOperations.ZeroMemory(cipher); }
    }

    internal void Delete()
    {
        RequireProtectedFile();
        File.Delete(_file);
        if (File.Exists(_file))
            throw new IOException("Protected key file could not be removed");
    }

    internal string TestFile => _file;
}
