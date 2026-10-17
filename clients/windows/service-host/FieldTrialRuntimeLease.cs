#if ENABLE_ATTENDED_FIELD_TRIAL
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OracleProxy.WireGuardHost;

// R81 *diagnostic-build-only* runtime gate. Production builds do not
// contain this class or accept lab-field. This is NOT a complete field
// activation, signed operator consent, WFP policy or watchdog.
internal static class FieldTrialRuntimeLease
{
    private const string Profile = "lab-field";
    private const string Mode = "supervised_single_peer_no_default";
    private const string ClientInner = "Address = 10.77.72.2/32";
    private const string ServerInner = "AllowedIPs = 10.77.72.1/32";
    private static readonly HashSet<string> Keys = new(StringComparer.Ordinal)
    {
        "schema_version", "mode", "client_inner_ipv4", "server_inner_ipv4",
        "allowed_ips", "server_endpoint_ipv4", "server_udp_port",
        "server_public_key", "config_sha256", "issued_utc", "expires_utc",
        "separate_operator_approval_required", "operator_confirmation_recorded"
    };

    internal static void Require(string configPath)
    {
        if (!OperatingSystem.IsWindows() ||
            !Path.GetFullPath(configPath).Equals(
                Path.GetFullPath(EngineBundle.FixedConfigPath(Profile)),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Field profile path not fixed");
        string dir = Path.GetDirectoryName(configPath)!;
        string leasePath = Path.Combine(dir, "lab-field-lease.json");
        ConfigAclGate.RequireProtectedLabSealedFile(configPath);
        ConfigAclGate.RequireProtectedLabSealedFile(leasePath);
        var leaseInfo = new FileInfo(leasePath);
        var confInfo = new FileInfo(configPath);
        if (leaseInfo.Length is < 10 or > 4096 ||
            confInfo.Length is < 10 or > 1024)
            throw new InvalidOperationException("Field lease or config size invalid");
        using var stream = File.OpenRead(leasePath);
        using JsonDocument doc = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            MaxDepth = 3, CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false
        });
        string config = File.ReadAllText(configPath, Encoding.UTF8);
        if (!Validate(config, doc.RootElement, DateTimeOffset.UtcNow))
            throw new InvalidOperationException("Expiring field trial scope refused");
    }

    private static bool Key(string line, string prefix)
    {
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) return false;
        string value = line[prefix.Length..];
        if (value.Length != 44 || !value.EndsWith('=')) return false;
        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromBase64String(value);
            return bytes.Length == 32 && bytes.Any(b => b != 0) &&
                   Convert.ToBase64String(bytes) == value;
        }
        catch (FormatException) { return false; }
        finally { if (bytes != null) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static bool PublicIpv4(string text)
    {
        if (!IPAddress.TryParse(text, out IPAddress? ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            ip.ToString() != text)
            return false;
        byte[] b = ip.GetAddressBytes();
        // Reject loopback, private, link local, CGNAT, documentation,
        // benchmarking, multicast and reserved ranges for a public peer.
        if (b[0] is 0 or 10 or 127 or >= 224 ||
            (b[0] == 100 && b[1] is >= 64 and <= 127) ||
            (b[0] == 169 && b[1] == 254) ||
            (b[0] == 172 && b[1] is >= 16 and <= 31) ||
            (b[0] == 192 && b[1] is 0 or 168) ||
            (b[0] == 192 && b[1] == 88 && b[2] == 99) ||
            (b[0] == 192 && b[1] == 0 && b[2] == 2) ||
            (b[0] == 198 && b[1] is 18 or 19) ||
            (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
            (b[0] == 203 && b[1] == 0 && b[2] == 113))
            return false;
        return true;
    }

    internal static bool AcceptExactText(string? text, string endpoint,
        string serverPublic)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 1024 ||
            !text.EndsWith('\n') || text.Contains('\r') ||
            text.Any(c => (c < 32 && c != '\n') || c > 126))
            return false;
        string[] lines = text.Split('\n');
        if (lines.Length != 10 || lines[^1] != "" ||
            lines[0] != "[Interface]" || lines[2] != ClientInner ||
            lines[3] != "" || lines[4] != "[Peer]" ||
            lines[6] != ServerInner ||
            lines[7] != "Endpoint = " + endpoint + ":51828" ||
            lines[8] != "PersistentKeepalive = 25")
            return false;
        return Key(lines[1], "PrivateKey = ") &&
               Key(lines[5], "PublicKey = ") &&
               lines[5] == "PublicKey = " + serverPublic &&
               !string.Equals(lines[1][13..], lines[5][12..],
                   StringComparison.Ordinal);
    }

    private static string RequireString(JsonElement doc, string name) =>
        doc.GetProperty(name).GetString() ??
        throw new InvalidOperationException("Field lease missing required string");

    private static bool Time(string raw, out DateTimeOffset result) =>
        DateTimeOffset.TryParseExact(raw, "yyyy-MM-ddTHH:mm:ssZ",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal,
            out result);

    internal static bool Validate(string text, JsonElement doc,
        DateTimeOffset now)
    {
        try
        {
            if (doc.ValueKind != JsonValueKind.Object) return false;
            HashSet<string> seen = new(StringComparer.Ordinal);
            foreach (JsonProperty property in doc.EnumerateObject())
                if (!Keys.Contains(property.Name) || !seen.Add(property.Name))
                    return false;
            if (seen.Count != Keys.Count ||
                doc.GetProperty("schema_version").GetInt32() != 1 ||
                RequireString(doc, "mode") != Mode ||
                RequireString(doc, "client_inner_ipv4") != "10.77.72.2/32" ||
                RequireString(doc, "server_inner_ipv4") != "10.77.72.1/32" ||
                doc.GetProperty("server_udp_port").GetInt32() != 51828 ||
                doc.GetProperty("separate_operator_approval_required").GetBoolean() != true ||
                doc.GetProperty("operator_confirmation_recorded").GetBoolean() != true)
                return false;

            JsonElement allowed = doc.GetProperty("allowed_ips");
            if (allowed.ValueKind != JsonValueKind.Array ||
                allowed.GetArrayLength() != 1 ||
                allowed[0].GetString() != "10.77.72.1/32")
                return false;
            string ip = RequireString(doc, "server_endpoint_ipv4");
            string serverPublic = RequireString(doc, "server_public_key");
            if (!PublicIpv4(ip) ||
                !Key("PublicKey = " + serverPublic, "PublicKey = ") ||
                !AcceptExactText(text, ip, serverPublic))
                return false;
            if (!Time(RequireString(doc, "issued_utc"), out DateTimeOffset issued) ||
                !Time(RequireString(doc, "expires_utc"), out DateTimeOffset expires))
                return false;
            now = now.ToUniversalTime();
            if (issued > now || expires <= now ||
                now - issued > TimeSpan.FromMinutes(5) ||
                expires - issued > TimeSpan.FromMinutes(20) ||
                expires - issued < TimeSpan.FromMinutes(1))
                return false;
            string hash = RequireString(doc, "config_sha256");
            if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
                return false;
            byte[] actual = SHA256.HashData(Encoding.UTF8.GetBytes(text));
            byte[] wanted = Convert.FromHexString(hash);
            try { return CryptographicOperations.FixedTimeEquals(actual, wanted); }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(wanted);
            }
        }
        catch (Exception e) when (e is InvalidOperationException or FormatException
                                 or KeyNotFoundException or ArgumentException)
        {
            return false;
        }
    }

    private static bool CiContext() =>
        OperatingSystem.IsWindows() &&
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
        Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted" &&
        Environment.GetEnvironmentVariable("RUNNER_OS") == "Windows" &&
        Environment.GetEnvironmentVariable("ORACLE_R81") == "CI_ONLY";

    internal static int CiReview()
    {
        if (!CiContext()) return 3;
        try
        {
            Require(EngineBundle.FixedConfigPath(Profile));
            Console.WriteLine("R81_PROTECTED_EXPIRING_FIELD_LEASE_SCOPE_REVIEW_PASS");
            Console.WriteLine("R81_NETWORK_ACTIVATION_APPROVED=false");
            return 0;
        }
        catch { return 3; }
    }

    internal static int SelfTest()
    {
        if (!CiContext()) return 3;
        string client=Convert.ToBase64String(Enumerable.Range(1,32).Select(x=>(byte)x).ToArray());
        string server=Convert.ToBase64String(Enumerable.Range(33,32).Select(x=>(byte)x).ToArray());
        string cfg="[Interface]\nPrivateKey = "+client+
            "\nAddress = 10.77.72.2/32\n\n[Peer]\nPublicKey = "+server+
            "\nAllowedIPs = 10.77.72.1/32\nEndpoint = 8.8.8.8:51828\nPersistentKeepalive = 25\n";
        DateTimeOffset now=DateTimeOffset.UtcNow;
        var lease = new Dictionary<string, object>
        {
            ["schema_version"]=1, ["mode"]=Mode,
            ["client_inner_ipv4"]="10.77.72.2/32",
            ["server_inner_ipv4"]="10.77.72.1/32",
            ["allowed_ips"]=new[]{"10.77.72.1/32"},
            ["server_endpoint_ipv4"]="8.8.8.8",["server_udp_port"]=51828,
            ["server_public_key"]=server,
            ["config_sha256"]=Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(cfg))),
            ["issued_utc"]=now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["expires_utc"]=now.AddMinutes(10).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["separate_operator_approval_required"]=true,
            ["operator_confirmation_recorded"]=true
        };
        using JsonDocument json=JsonDocument.Parse(JsonSerializer.Serialize(lease));
        if (!Validate(cfg,json.RootElement,now)) return 1;
        string[] bad={
            cfg.Replace("AllowedIPs = 10.77.72.1/32","AllowedIPs = 0.0.0.0/0"),
            cfg.Replace("Endpoint = 8.8.8.8:51828","Endpoint = 127.0.0.1:51828"),
            cfg.Replace("Endpoint = 8.8.8.8:51828","Endpoint = 8.8.8.8:443"),
            cfg.Replace("Address = 10.77.72.2/32","Address = 10.77.72.2/24"),
            cfg+"PreUp = injected\n",
            cfg+"[Peer]\n",
            cfg.Replace("\n","\r\n")
        };
        if (bad.Any(s=>AcceptExactText(s,"8.8.8.8",server))) return 1;
        if (Validate(cfg,json.RootElement,now.AddMinutes(22))) return 1;
        if (PublicIpv4("127.0.0.1") || PublicIpv4("10.0.0.6") ||
            PublicIpv4("198.51.100.1") || PublicIpv4("203.0.113.1") ||
            PublicIpv4("0.0.0.0") || PublicIpv4("224.0.0.1") ||
            !PublicIpv4("8.8.8.8"))
            return 1;
        Console.WriteLine("R81_FIELD_TRIAL_COMPILE_ONLY_SCOPE_NEGATIVE_TEST_PASS");
        return 0;
    }
}
#endif
