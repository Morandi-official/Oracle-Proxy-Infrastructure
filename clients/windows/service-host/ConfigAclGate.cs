using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace OracleProxy.WireGuardHost;

/// <summary>
/// Read-only ACL gate before *future* privileged DLL activation. No ACLs are
/// created or modified by this service. Secure provisioning must be reviewed
/// separately and occur only on an isolated lab machine.
/// </summary>
internal static class ConfigAclGate
{
    private static readonly string LocalSystemSid =
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;
    private static readonly string LocalAdministratorsSid =
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;

    internal static void RequireProtectedLabInstallation(
        string dllDirectory, string labConfigFile, string profile = "lab-only")
    {
        string appData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);
        string labRoot = Path.Combine(appData, "OracleProxyLab");
        string configFolder = Path.Combine(labRoot, "config");

        if (!string.Equals(Path.GetFullPath(labConfigFile),
                Path.GetFullPath(EngineBundle.FixedConfigPath(profile)),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lab config path is not fixed");

        // For a real deployment this gate must be paired with a separately
        // audited SCM installer and signed upstream DLL chain.
        foreach (string dir in new[] { dllDirectory, labRoot, configFolder })
            RequireDirectoryProtected(dir);

        foreach (string binary in new[] {
            EngineBundle.TunnelFile, EngineBundle.DriverFile,
            EngineBundle.ManifestFile
        })
            RequireFileProtected(Path.Combine(dllDirectory, binary), false);

        RequireFileProtected(labConfigFile, true);
    }

    private static void RequireDirectoryProtected(string path)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Invalid protected directory");
        InspectAcl(dir.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access),
            secretFile: false, new HashSet<string> { LocalSystemSid, LocalAdministratorsSid });
    }

    private static void RequireFileProtected(string path, bool secret)
    {
        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Invalid protected file");
        InspectAcl(file.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access),
            secret, new HashSet<string> { LocalSystemSid, LocalAdministratorsSid });
    }

    // Test-only owner injection. Never used by the native service runtime.
    internal static void AssertProtectedFixture(string path, string testOwner)
    {
        var file = new FileInfo(path);
        InspectAcl(file.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access),
            secretFile: true, new HashSet<string> { testOwner, LocalSystemSid,
                LocalAdministratorsSid });
    }

    private static void InspectAcl(FileSystemSecurity acl, bool secretFile,
        HashSet<string> trustedOwnersAndWriters)
    {
        if (!acl.AreAccessRulesProtected)
            throw new InvalidOperationException("Inherited ACL must be disabled");
        string? owner = (acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
        if (owner is null || !trustedOwnersAndWriters.Contains(owner))
            throw new InvalidOperationException("Untrusted config or binary owner");

        var writePermissions = FileSystemRights.Write |
            FileSystemRights.Modify | FileSystemRights.FullControl |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            var sid = (rule.IdentityReference as SecurityIdentifier)?.Value;
            if (sid is null)
                throw new InvalidOperationException("Unrecognized ACE identity");
            if (trustedOwnersAndWriters.Contains(sid))
                continue;
            if (secretFile || (rule.FileSystemRights & writePermissions) != 0)
                throw new InvalidOperationException("Untrusted access to protected files");
        }
    }
}
