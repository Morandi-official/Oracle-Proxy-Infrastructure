using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace OracleProxy.IntentLab;

// A real Windows DPAPI/NTFS transactional recovery journal for disposable CI,
// not a production VPN actuator. WFP, SCM and NTFS CANNOT commit atomically
// together. Every partial transition remains pending a separate OS audit.
internal enum RecoveryPhase
{
    UnknownFailClosed,
    ConnectPrepared,
    ProtectedConnected,
    DisconnectPrepared,
    GuardReleasePending,
    OffRecordedNeedsOsAudit,
    Quarantined
}
internal readonly record struct RecoveryRecord(
    RecoveryPhase Phase, long Revision, Guid TransactionId, string Reason)
{
    // Do not interpret stored Off as evidence that OS traffic was restored.
    internal bool RequiresExternalWfpAudit => true;
    internal bool MayAutomaticallyReleaseWfp => false;
}

internal sealed class DurableRecoveryLedger
{
    private const string Filename = "transition-ledger.dpapi";
    private const string Context = "OracleProxy.R32.DisposableRecoveryJournal.v1";
    private static readonly byte[] Entropy = Encoding.ASCII.GetBytes(Context);
    private static readonly SecurityIdentifier Admin =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);
    private readonly string _file;
    private readonly object _sync = new();

    private sealed record Payload(int schema_version, string context,
        string phase, long revision, string transaction_id);
    internal DurableRecoveryLedger(string folder)
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
            throw new InvalidOperationException("R32 test journal only");
        if (string.IsNullOrWhiteSpace(folder) || !Path.IsPathFullyQualified(folder))
            throw new ArgumentException("Journal folder must be absolute");
        string runnerRoot = Path.GetFullPath(Environment.GetEnvironmentVariable("RUNNER_TEMP")
            ?? throw new InvalidOperationException("No disposable runner root"));
        string full = Path.GetFullPath(folder);
        if (!full.StartsWith(runnerRoot.TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Cannot use non-disposable journal folder");
        _file = Path.Combine(full, Filename);
        RequireProtectedDirectory(full);
    }

    internal static void ProtectFreshTestFolder(string folder)
    {
        var dir = new DirectoryInfo(folder);
        if (!dir.Exists || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Unsafe test folder");
        var acl = new DirectorySecurity();
        acl.SetOwner(Admin);
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { Admin, System })
            acl.AddAccessRule(new FileSystemAccessRule(sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(acl);
    }

    private static void VerifyAcl(FileSystemSecurity acl)
    {
        if (!acl.AreAccessRulesProtected)
            throw new InvalidOperationException("Inherited journal ACL");
        var owner = (SecurityIdentifier?)acl.GetOwner(typeof(SecurityIdentifier));
        if (owner?.Value != Admin.Value && owner?.Value != System.Value)
            throw new InvalidOperationException("Unexpected journal owner");
        foreach (FileSystemAccessRule ace in acl.GetAccessRules(true, true,
                     typeof(SecurityIdentifier)))
            if (ace.AccessControlType == AccessControlType.Allow &&
                ace.IdentityReference.Value != Admin.Value &&
                ace.IdentityReference.Value != System.Value)
                throw new InvalidOperationException("Untrusted journal ACE");
    }

    private static void RequireProtectedDirectory(string path)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Unsafe journal directory");
        VerifyAcl(dir.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access));
    }

    private void RequireProtectedFile()
    {
        RequireProtectedDirectory(Path.GetDirectoryName(_file)!);
        var fi = new FileInfo(_file);
        if (!fi.Exists || (fi.Attributes & FileAttributes.ReparsePoint) != 0 ||
            fi.Length is < 1 or > 4096)
            throw new InvalidOperationException("Unsafe journal file");
        VerifyAcl(fi.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access));
    }

    internal RecoveryRecord Read()
    {
        lock (_sync)
        {
            if (!File.Exists(_file))
                return new(RecoveryPhase.UnknownFailClosed, 0, Guid.Empty,
                    "MISSING_OR_DELETED_FAIL_CLOSED");
            byte[]? cipher = null;
            byte[]? plain = null;
            try
            {
                RequireProtectedFile();
                cipher = File.ReadAllBytes(_file);
                plain = ProtectedData.Unprotect(cipher, Entropy,
                    DataProtectionScope.LocalMachine);
                using var doc = JsonDocument.Parse(plain, new JsonDocumentOptions {
                    AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 2
                });
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object) throw new FormatException();
                var fields = new HashSet<string>(StringComparer.Ordinal);
                foreach (var prop in root.EnumerateObject())
                    if (prop.Name is not ("schema_version" or "context" or "phase" or
                            "revision" or "transaction_id") || !fields.Add(prop.Name))
                        throw new FormatException();
                if (fields.Count != 5 ||
                    root.GetProperty("schema_version").GetInt32() != 1 ||
                    root.GetProperty("context").GetString() != Context ||
                    !root.GetProperty("revision").TryGetInt64(out long revision) ||
                    revision < 1 ||
                    !Guid.TryParseExact(root.GetProperty("transaction_id").GetString(),
                        "D", out Guid tx) || tx == Guid.Empty ||
                    !Enum.TryParse<RecoveryPhase>(root.GetProperty("phase").GetString(),
                        false, out var phase) ||
                    phase is RecoveryPhase.UnknownFailClosed or RecoveryPhase.Quarantined)
                    throw new FormatException();
                return new(phase, revision, tx, "RECOVERED_REQUIRES_OS_AUDIT");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                CryptographicException or JsonException or FormatException or
                InvalidOperationException or KeyNotFoundException or ArgumentException)
            {
                return new(RecoveryPhase.Quarantined, 0, Guid.Empty,
                    "UNREADABLE_OR_TAMPERED_FAIL_CLOSED");
            }
            finally
            {
                if (plain is not null) CryptographicOperations.ZeroMemory(plain);
                if (cipher is not null) CryptographicOperations.ZeroMemory(cipher);
            }
        }
    }

    // A SYSTEM-owned controller would call these in order after independently
    // proving the OS state; this CI-only ledger never performs that proof.
    // No transition can delete or release a WFP rule, even for stored Off.
    internal RecoveryRecord Advance(RecoveryPhase expected, RecoveryPhase next,
        Guid transactionId)
    {
        lock (_sync)
        {
            if (transactionId == Guid.Empty || !Allowed(expected, next))
                throw new InvalidOperationException("Invalid journal transition");
            var previous = Read();
            if (previous.Phase != expected ||
                previous.Phase == RecoveryPhase.Quarantined ||
                (previous.Revision > 0 && previous.TransactionId != transactionId))
                throw new InvalidOperationException("Journal state does not match");
            long revision = checked(previous.Revision + 1);
            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(new Payload(
                1, Context, next.ToString(), revision, transactionId.ToString("D")));
            byte[]? cipher = null;
            string temporary = _file + "." + Guid.NewGuid().ToString("N") + ".staging";
            try
            {
                cipher = ProtectedData.Protect(plain, Entropy,
                    DataProtectionScope.LocalMachine);
                if (cipher.Length > 4096)
                    throw new InvalidOperationException("Journal ciphertext too large");
                // The protected parent supplies Admin/SYSTEM-only inheritance,
                // but set an explicit protected ACL BEFORE writing ciphertext.
                using (var fs = new FileStream(temporary, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    var acl = new FileSecurity();
                    acl.SetOwner(Admin);
                    acl.SetAccessRuleProtection(true, false);
                    foreach (var sid in new[] { Admin, System })
                        acl.AddAccessRule(new FileSystemAccessRule(
                            sid, FileSystemRights.FullControl, AccessControlType.Allow));
                    new FileInfo(temporary).SetAccessControl(acl);
                    fs.Write(cipher);
                    fs.Flush(flushToDisk: true);
                }
                // Same-volume rename commits a single journal record. Does NOT
                // make SCM/NTFS/WFP one atomic transaction.
                File.Move(temporary, _file, overwrite: true);
                RecoveryRecord result = Read();
                if (result.Phase != next || result.Revision != revision ||
                    result.TransactionId != transactionId)
                    throw new InvalidOperationException("Unverified journal commit");
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
                if (cipher is not null) CryptographicOperations.ZeroMemory(cipher);
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
    }

    private static bool Allowed(RecoveryPhase from, RecoveryPhase to) =>
        (from, to) switch {
            (RecoveryPhase.UnknownFailClosed, RecoveryPhase.ConnectPrepared) => true,
            (RecoveryPhase.ConnectPrepared, RecoveryPhase.ProtectedConnected) => true,
            (RecoveryPhase.ProtectedConnected, RecoveryPhase.DisconnectPrepared) => true,
            (RecoveryPhase.DisconnectPrepared, RecoveryPhase.GuardReleasePending) => true,
            (RecoveryPhase.GuardReleasePending, RecoveryPhase.OffRecordedNeedsOsAudit) => true,
            _ => false
        };
}
