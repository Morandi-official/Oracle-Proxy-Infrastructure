using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.WireGuardHost;

// Exact allowlist and integrity preflight for a LAB-ONLY service.
// This is NOT a replacement for signed-binary provenance, directory ACL
// enforcement, code-signing review or secure production config storage.
internal static class EngineBundle
{
    internal const string TunnelFile = "tunnel.dll";
    internal const string DriverFile = "wireguard.dll";
    internal const string ManifestFile = "engine-pins.json";
    internal const string FixedLabConfigFile = "lab-only.conf";

    internal sealed record VerifiedFiles(string TunnelDll, string WireGuardDll, string Config);

    internal static bool IsAllowedLabProfile(string profile) =>
        profile is "lab-only" or "lab-peer-a" or "lab-peer-b"
#if ENABLE_ATTENDED_FIELD_TRIAL
        or "lab-field"
#endif
        ;

    internal static string FixedConfigPath(string profile)
    {
        if (!IsAllowedLabProfile(profile))
            throw new InvalidOperationException("Profile is not in the static lab allowlist");
        string root = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidOperationException("Unresolved ProgramData");
        return Path.Combine(root, "OracleProxyLab", "config", profile + ".conf");
    }

    internal static string FixedConfigPath()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidOperationException("Unresolved ProgramData");
        return Path.Combine(root, "OracleProxyLab", "config", FixedLabConfigFile);
    }

    internal static VerifiedFiles Verify(string directory, string configPath)
    {
        if (!Path.IsPathFullyQualified(directory) || !Path.IsPathFullyQualified(configPath))
            throw new InvalidOperationException("Relative paths prohibited");

        directory = Path.GetFullPath(directory);
        configPath = Path.GetFullPath(configPath);
        if (!new[] {
            FixedLabConfigFile, "lab-peer-a.conf", "lab-peer-b.conf"
#if ENABLE_ATTENDED_FIELD_TRIAL
            , "lab-field.conf"
#endif
        }.Contains(Path.GetFileName(configPath), StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only fixed lab config name allowed");

        CheckRealDirectory(directory);
        CheckRealDirectory(Path.GetDirectoryName(configPath)!);

        string tunnel = Path.Combine(directory, TunnelFile);
        string driver = Path.Combine(directory, DriverFile);
        string manifest = Path.Combine(directory, ManifestFile);
        CheckRegularFile(tunnel, 20_000_000);
        CheckRegularFile(driver, 20_000_000);
        CheckRegularFile(manifest, 4096);
        CheckRegularFile(configPath, 65536);
        RejectScriptHooks(configPath);

        using var stream = File.OpenRead(manifest);
        using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            MaxDepth = 2,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false
        });
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Invalid manifest");

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (property.Name is not ("schema_version" or "tunnel_sha256" or
                "wireguard_sha256" or "config_sha256") ||
                !names.Add(property.Name))
                throw new InvalidOperationException("Unexpected or duplicate pin");
        }
        if (names.Count != 4 || !root.TryGetProperty("schema_version", out var version) ||
            version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out int numericVersion) || numericVersion != 1)
            throw new InvalidOperationException("Invalid manifest version");

        VerifyHash(tunnel, root.GetProperty("tunnel_sha256"));
        VerifyHash(driver, root.GetProperty("wireguard_sha256"));
        VerifyHash(configPath, root.GetProperty("config_sha256"));
        return new VerifiedFiles(tunnel, driver, configPath);
    }

    private static void CheckRegularFile(string path, long limit)
    {
        FileInfo info = new(path);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (info.Attributes & FileAttributes.Directory) != 0 ||
            info.Length == 0 || info.Length > limit)
            throw new InvalidOperationException("Missing, unsafe or oversized pinned file");
    }

    private static void CheckRealDirectory(string path)
    {
        DirectoryInfo info = new(path);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Unsafe directory");
    }

    private static void RejectScriptHooks(string path)
    {
        using StreamReader reader = new(path);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (Regex.IsMatch(line, @"^\s*(PreUp|PostUp|PreDown|PostDown)\s*=",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Script hooks forbidden");
        }
    }

    private static void VerifyHash(string file, JsonElement pin)
    {
        if (pin.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("Invalid binary pin");
        string? expected = pin.GetString();
        if (expected is null || !Regex.IsMatch(expected, @"\A[0-9a-fA-F]{64}\z"))
            throw new InvalidOperationException("Invalid SHA-256 pin");
        using FileStream stream = File.OpenRead(file);
        byte[] actual = SHA256.HashData(stream);
        if (!CryptographicOperations.FixedTimeEquals(
                actual, Convert.FromHexString(expected)))
            throw new InvalidOperationException("SHA-256 mismatch");
    }
}
