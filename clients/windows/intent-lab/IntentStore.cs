using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OracleProxy.IntentLab;

// A stand-alone OFFLINE persistence experiment. Never loaded by a Windows
// service, installed on a client or invoked by the released GUI.
// Specifically, bool RequiresFailClosed does NOT apply a WFP rule.
internal enum UserIntent
{
    UnknownFailClosed = 0,
    Enabled = 1,
    Disabled = 2
}

internal sealed record IntentSnapshot(UserIntent Intent, long Revision, string Reason)
{
    internal bool RequiresFailClosed => Intent != UserIntent.Disabled;
}

internal sealed class IntentStore
{
    private const int MaxBlobBytes = 4096;
    private const string Context = "OracleProxy.IntentLab.v1.Windows-DPAPI";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes(Context);
    private readonly string _file;

    // Only isolated self-tests may supply an alternative path. Production
    // persistence will need its own service SID / ACL / OS-token review.
    internal IntentStore(string directory, string filename)
    {
        if (!Path.IsPathFullyQualified(directory) ||
            filename is not "intent.protected")
            throw new ArgumentException("Only fixed intent filename in an absolute directory");
        var info = new DirectoryInfo(directory);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Intent store directory unsafe");
        _file = Path.Combine(info.FullName, filename);
    }

    private sealed record JsonRecord(
        int schema_version, string context, string explicit_intent,
        long revision, string record_id);

    internal IntentSnapshot Read()
    {
        try
        {
            var info = new FileInfo(_file);
            if (!info.Exists)
                return new(UserIntent.UnknownFailClosed, 0, "MISSING_FILE");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 ||
                info.Length is < 1 or > MaxBlobBytes)
                return new(UserIntent.UnknownFailClosed, 0, "INVALID_FILE");
            byte[] encrypted = File.ReadAllBytes(_file);
            byte[] plain = ProtectedData.Unprotect(encrypted, Entropy,
                DataProtectionScope.LocalMachine);
            try
            {
                if (plain.Length is < 1 or > MaxBlobBytes)
                    return new(UserIntent.UnknownFailClosed, 0, "INVALID_RECORD");
                using JsonDocument json = JsonDocument.Parse(plain, new JsonDocumentOptions {
                    MaxDepth = 3, AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow
                });
                var root = json.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    return new(UserIntent.UnknownFailClosed, 0, "INVALID_RECORD");
                var fields = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in root.EnumerateObject())
                    if (p.Name is not ("schema_version" or "context" or
                                      "explicit_intent" or "revision" or "record_id")
                        || !fields.Add(p.Name))
                        return new(UserIntent.UnknownFailClosed, 0, "INVALID_RECORD");
                if (fields.Count != 5 ||
                    root.GetProperty("schema_version").GetInt32() != 1 ||
                    root.GetProperty("context").GetString() != Context ||
                    root.GetProperty("revision").ValueKind != JsonValueKind.Number ||
                    !root.GetProperty("revision").TryGetInt64(out long revision) ||
                    revision < 1 ||
                    !Guid.TryParseExact(root.GetProperty("record_id").GetString(),
                        "D", out var guid) || guid == Guid.Empty)
                    return new(UserIntent.UnknownFailClosed, 0, "INVALID_RECORD");
                return root.GetProperty("explicit_intent").GetString() switch {
                    "Enabled" => new(UserIntent.Enabled, revision, "EXPLICIT_ENABLED"),
                    "Disabled" => new(UserIntent.Disabled, revision, "EXPLICIT_DISABLED"),
                    _ => new(UserIntent.UnknownFailClosed, 0, "INVALID_RECORD")
                };
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
            CryptographicException or JsonException or FormatException or
            InvalidOperationException or KeyNotFoundException)
        {
            return new(UserIntent.UnknownFailClosed, 0, "UNREADABLE_OR_TAMPERED");
        }
    }

    // There is deliberately NO automatic recovery-to-Off. A real privileged
    // caller MUST verify OS identity and explicit choice before ever exposing
    // any equivalent of this method to the application.
    internal IntentSnapshot RecordExplicitChoice(UserIntent choice)
    {
        if (choice is not (UserIntent.Enabled or UserIntent.Disabled))
            throw new ArgumentException("Only explicit ON or OFF choice is valid");
        bool alreadyExists = File.Exists(_file);
        var previous = Read();
        if (alreadyExists && previous.Intent == UserIntent.UnknownFailClosed)
            throw new InvalidOperationException("Corrupt state requires separate recovery");
        if (!alreadyExists && choice == UserIntent.Disabled)
            throw new InvalidOperationException("Missing state cannot silently initialize Off");

        long revision = checked(previous.Revision + 1);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new JsonRecord(
            1, Context, choice.ToString(), revision, Guid.NewGuid().ToString("D")));
        byte[] encrypted;
        try {
            encrypted = ProtectedData.Protect(payload, Entropy,
                DataProtectionScope.LocalMachine);
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
        if (encrypted.Length > MaxBlobBytes)
            throw new InvalidOperationException("Intent blob too large");
        string temporary = _file + "." + Guid.NewGuid().ToString("N") + ".staging";
        try
        {
            // Same-directory create-new/write-through then atomic rename.
            // The surrounding directory MUST have a protected ACL, but this
            // prototype does NOT prove directory ACLs or resist privileged replay.
            using (var output = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                output.Write(encrypted);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, _file, overwrite: true);
        }
        finally {
            CryptographicOperations.ZeroMemory(encrypted);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
        return Read();
    }
}
