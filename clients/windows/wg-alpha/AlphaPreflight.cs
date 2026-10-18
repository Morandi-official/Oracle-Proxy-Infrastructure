using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace OracleProxy.WgAlpha;

// Does not read keys into a log, change routes, query the Internet or call
// elevated commands. Alpha requires one exact config basename for ownership.
internal static class AlphaPreflight
{
    internal const string FixedName = "OracleProxyAlphaTest";
    internal const string FixedService = "WireGuardTunnel$OracleProxyAlphaTest";
    internal const string Unverified = "NOT_TESTED";
    private const int MaxBytes = 64 * 1024;

    internal static bool Administrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    internal static bool SafeName(string path) =>
        !string.IsNullOrWhiteSpace(path) &&
        string.Equals(Path.GetFileName(path), FixedName + ".conf",
            StringComparison.OrdinalIgnoreCase) &&
        Path.IsPathFullyQualified(path);

    // No arbitrary hook commands or default-route "/0" semantics. The
    // official WireGuard client can install a restrictive firewall kill
    // switch on /0. A paired /1 route covers IPv4 destinations without
    // enabling that specific automatic /0 behavior. NOT leak protection.
    internal static string ValidateText(string text)
    {
        if (text.Length > MaxBytes || text.IndexOf('\0') >= 0)
            return "UNSUPPORTED_CONFIG";
        bool iface = false, peer = false, allowed = false;
        bool halfA = false, halfB = false;
        string section = "";
        foreach (string untrimmed in text.Split('\n'))
        {
            string line = untrimmed.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                continue;
            if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase)) {
                if (iface || peer) return "UNSUPPORTED_CONFIG";
                iface = true; section = "interface"; continue;
            }
            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase)) {
                if (!iface || peer) return "UNSUPPORTED_CONFIG";
                peer = true; section = "peer"; continue;
            }
            if (!iface || line.StartsWith('[')) return "UNSUPPORTED_CONFIG";
            var split = line.IndexOf('=');
            if (split < 1) return "UNSUPPORTED_CONFIG";
            string key = line[..split].Trim();
            string value = line[(split + 1)..].Trim();
            if (key.Equals("PreUp", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("PostUp", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("PreDown", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("PostDown", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Table", StringComparison.OrdinalIgnoreCase))
                return "SCRIPTS_OR_ROUTING_OVERRIDES_FORBIDDEN";
            if (key.Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase)) {
                if (section != "peer" || allowed) return "UNSUPPORTED_CONFIG";
                allowed = true;
                foreach (string item in value.Split(',')) {
                    // Accept only exact CIDR tokens; reject comments, hidden
                    // alternate spellings, extra values and every /0. The
                    // official tunnel must never acquire a /0 kill-switch by
                    // exploiting differences in the preflight parser.
                    string ip = item.Trim();
                    string[] cidr = ip.Split('/');
                    if (cidr.Length != 2 ||
                        !System.Net.IPAddress.TryParse(cidr[0], out var address) ||
                        !int.TryParse(cidr[1], out int prefix) ||
                        prefix < 0 ||
                        prefix > (address.AddressFamily ==
                            System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))
                        return "UNSUPPORTED_ALLOWED_IPS_FORMAT";
                    if (prefix == 0) return "DEFAULT_ROUTE_KILLSWITCH_RISK_DENY";
                    string normalized = address + "/" + prefix;
                    if (normalized == "0.0.0.0/1") halfA = true;
                    if (normalized == "128.0.0.0/1") halfB = true;
                }
            }
        }
        if (!iface || !peer || !allowed || halfA != halfB)
            return "UNSUPPORTED_OR_UNPAIRED_IPV4_ROUTE";
        return "CONFIG_SHAPE_OK_NOT_NETWORK_PROOF";
    }

    internal static string CheckFile(string path)
    {
        if (!SafeName(path) || !OperatingSystem.IsWindows())
            return "REFUSED_CONFIG_FILE_NAME_OR_PLATFORM";
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists || file.Length < 32 || file.Length > MaxBytes ||
                file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Directory is null || file.Directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return "REFUSED_FILE_SIZE_OR_LINK";
            // PrivateKey is processed only by the official WireGuard service.
            // This short-lived managed scan sees text but never logs/exports it.
            return ValidateText(File.ReadAllText(path, new UTF8Encoding(false, true)));
        }
        catch { return "CONFIG_UNREADABLE"; }
    }

    internal static bool SelfTest()
    {
        const string prefix="[Interface]\nPrivateKey = synthetic-test-only\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = synthetic-test-only\nEndpoint = 127.0.0.1:1\n";
        return ValidateText(prefix+"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n") == "CONFIG_SHAPE_OK_NOT_NETWORK_PROOF"
            && ValidateText(prefix+"AllowedIPs = 0.0.0.0/0\n") == "DEFAULT_ROUTE_KILLSWITCH_RISK_DENY"
            && ValidateText(prefix+"AllowedIPs = ::/0\n") == "DEFAULT_ROUTE_KILLSWITCH_RISK_DENY"
            && ValidateText(prefix+"AllowedIPs = 0.0.0.0/1\n") == "UNSUPPORTED_OR_UNPAIRED_IPV4_ROUTE"
            && ValidateText(prefix+"PostUp = cmd.exe /c something\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n") == "SCRIPTS_OR_ROUTING_OVERRIDES_FORBIDDEN"
            && !SafeName(@"C:\any\another.conf")
            && SafeName(@"C:\safe\OracleProxyAlphaTest.conf");
    }
}
