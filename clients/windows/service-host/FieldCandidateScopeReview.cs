using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace OracleProxy.WireGuardHost;

// R78: *only* a read-only offline trust boundary for an R77-owned synthetic
// config. This cannot install/start a service, open WireGuardNT, authorize a
// real external peer or produce a production profile.
internal static class FieldCandidateScopeReview
{
    private const string RootName = "OracleProxyR77Only";
    private const string Marker = "CI_R77_ONLY_DISPOSABLE_GITHUB_VM";
    private const string InnerClient = "Address = 10.77.72.2/32";
    private const string InnerServer = "AllowedIPs = 10.77.72.1/32";
    // R77 fixture uses a syntactically public but uncontacted test address.
    // Real operator endpoint provisioning is NOT supported in R78.
    private const string SyntheticEndpoint = "Endpoint = 8.8.8.8:51828";

    internal static bool ValidateExactProfile(string config)
    {
        if (string.IsNullOrEmpty(config) || config.Length > 512 ||
            config[^1] != '\n' || config.Contains('\r') ||
            config.Any(c => c < 0x20 && c != '\n' || c > 0x7e))
            return false;

        string[] lines = config.Split('\n');
        if (lines.Length != 10 || lines[^1] != "" ||
            lines[0] != "[Interface]" || lines[2] != InnerClient ||
            lines[3] != "" || lines[4] != "[Peer]" ||
            lines[6] != InnerServer || lines[7] != SyntheticEndpoint ||
            lines[8] != "PersistentKeepalive = 25")
            return false;

        return ValidKeyLine(lines[1], "PrivateKey = ") &&
               ValidKeyLine(lines[5], "PublicKey = ") &&
               !string.Equals(lines[1][13..], lines[5][12..],
                   StringComparison.Ordinal);
    }

    private static bool ValidKeyLine(string line, string prefix)
    {
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
            return false;
        string value = line[prefix.Length..];
        if (value.Length != 44 || !value.EndsWith('='))
            return false;
        byte[]? raw = null;
        try
        {
            raw = Convert.FromBase64String(value);
            if (raw.Length != 32 || raw.All(b => b == 0))
                return false;
            return string.Equals(Convert.ToBase64String(raw), value,
                StringComparison.Ordinal);
        }
        catch (FormatException) { return false; }
        finally { if (raw != null) Array.Clear(raw); }
    }

    private static bool CiContext() =>
        OperatingSystem.IsWindows() &&
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
        Environment.GetEnvironmentVariable("RUNNER_OS") == "Windows" &&
        Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted" &&
        Environment.GetEnvironmentVariable("ORACLE_R77") == "CI_ONLY" &&
        Environment.GetEnvironmentVariable("ORACLE_R78") == "CI_ONLY";

    internal static int ReviewOwnedStagedFile()
    {
        if (!CiContext()) return 3;
        try
        {
            using WindowsIdentity caller = WindowsIdentity.GetCurrent();
            if (!caller.IsAuthenticated ||
                !new WindowsPrincipal(caller).IsInRole(
                    WindowsBuiltInRole.Administrator))
                return 3;

            string basePath = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrWhiteSpace(basePath)) return 3;
            string root = Path.Combine(basePath, RootName);
            string marker = Path.Combine(root, ".r77-owned");
            string config = Path.Combine(root, "lab-peer-a.conf");

            var rootInfo = new DirectoryInfo(root);
            if (!rootInfo.Exists ||
                (rootInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                return 3;

            // Existing Windows native service preflight's independent
            // Admin/SYSTEM-only ACL validator: no ACL changes here.
            ConfigAclGate.RequireProtectedLabSealedFile(marker);
            ConfigAclGate.RequireProtectedLabSealedFile(config);
            if (File.ReadAllText(marker, Encoding.ASCII).Trim() != Marker)
                return 3;

            FileInfo info = new(config);
            if (info.Length is < 1 or > 512) return 3;
            // Read-only. Do not print private keys or endpoint fields.
            if (!ValidateExactProfile(File.ReadAllText(config, Encoding.UTF8)))
                return 3;
            Console.WriteLine("R78_NATIVE_HOST_READONLY_FIXED_FIELD_SCOPE_PASS");
            Console.WriteLine("R78_ACTIVATION_AUTHORIZED=false");
            return 0;
        }
        catch
        {
            // Logs never include exception paths, config contents or keys.
            return 3;
        }
    }

    internal static int SelfTest()
    {
        if (!CiContext()) return 3;
        byte[] a = Enumerable.Range(1, 32).Select(n => (byte)n).ToArray();
        byte[] b = Enumerable.Range(33, 32).Select(n => (byte)n).ToArray();
        string profile = "[Interface]\nPrivateKey = " +
            Convert.ToBase64String(a) + "\n" + InnerClient +
            "\n\n[Peer]\nPublicKey = " + Convert.ToBase64String(b) +
            "\n" + InnerServer + "\n" + SyntheticEndpoint +
            "\nPersistentKeepalive = 25\n";
        Array.Clear(a);
        Array.Clear(b);
        if (!ValidateExactProfile(profile)) return 1;
        var mutations = new[]
        {
            profile.Replace(InnerServer, "AllowedIPs = 0.0.0.0/0"),
            profile.Replace(InnerServer, "AllowedIPs = ::/0"),
            profile.Replace(InnerServer, "AllowedIPs = 10.77.72.0/24"),
            profile.Replace(InnerClient, "Address = 10.77.72.2/24"),
            profile.Replace(SyntheticEndpoint, "Endpoint = 152.67.156.100:51828"),
            profile.Replace(SyntheticEndpoint, "Endpoint = 8.8.8.8:51820"),
            profile.Replace("PersistentKeepalive = 25", "DNS = 1.1.1.1"),
            profile + "PostUp = cmd.exe\n",
            profile + "[Peer]\n",
            profile.Replace("\n", "\r\n"),
            profile.TrimEnd('\n'),
            profile.Replace("[Peer]", "[Interface]\n[Peer]"),
            profile.Replace("PrivateKey = ", "PrivateKey = BAD!"),
            profile.Replace("PublicKey = ", "PublicKey = BAD!"),
        };
        if (mutations.Any(ValidateExactProfile)) return 1;
        Console.WriteLine("R78_NATIVE_FIELD_GRAMMAR_NEGATIVE_TEST_PASS");
        return 0;
    }
}
