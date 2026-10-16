using System.Text.RegularExpressions;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// R56 GUI mirrors R55's narrow no-shell/no-SSH-option input contract.
internal static class SshInput
{
    internal sealed record Validated(string Host, string User, int Port,
        string KeyPath, string KnownHosts);

    internal static bool TryParse(string host, string user, string portText,
        string keyPath, out Validated? option)
    {
        option = null;
        if (string.IsNullOrWhiteSpace(host) ||
            host.Length > 253 ||
            !Regex.IsMatch(host,
                @"\A[a-zA-Z0-9][a-zA-Z0-9.-]*\z",
                RegexOptions.CultureInvariant) ||
            host.Contains("..", StringComparison.Ordinal) ||
            host.EndsWith(".", StringComparison.Ordinal) ||
            host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.IsNullOrEmpty(user) || user.Length > 32 ||
            !Regex.IsMatch(user, @"\A[a-zA-Z_][a-zA-Z0-9_.-]*\z",
                RegexOptions.CultureInvariant))
            return false;
        if (!int.TryParse(portText, out int port) || port is < 1 or > 65535)
            return false;
        if (string.IsNullOrWhiteSpace(keyPath) ||
            !Path.IsPathFullyQualified(keyPath)) return false;
        string key;
        try
        {
            key = Path.GetFullPath(keyPath);
            var info = new FileInfo(key);
            if (!info.Exists || info.Length is <= 0 or > 1048576 ||
                (info.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
        }
        catch { return false; }

        string knownHosts = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".ssh", "known_hosts");
        try
        {
            var info = new FileInfo(knownHosts);
            if (!info.Exists || info.Length is <= 0 or > 1048576 ||
                (info.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
        }
        catch { return false; }
        option = new Validated(host, user, port, key, knownHosts);
        return true;
    }

    internal static bool SelfTest()
    {
        string[] hosts = {
            "-oProxyCommand=evil", "a;whoami", "a@b", "a..b",
            "a b", "localhost", "a/"
        };
        string[] users = { "-o", "u;whoami", "u@b", "u b", "user\\n" };
        if (hosts.Any(h => ValidHostForTest(h)) ||
            users.Any(u => ValidUserForTest(u)) ||
            TryParse("127.0.0.1", "ubuntu", "22", "relative.key", out _) ||
            TryParse("127.0.0.1", "ubuntu", "notaport",
                "C:\\no-such-key.key", out _))
            return false;
        return true;
    }

    private static bool ValidHostForTest(string host) =>
        !string.IsNullOrWhiteSpace(host) && host.Length <= 253 &&
        Regex.IsMatch(host,
            @"\A[a-zA-Z0-9][a-zA-Z0-9.-]*\z",
            RegexOptions.CultureInvariant) &&
        !host.Contains("..") &&
        !host.EndsWith(".") &&
        !host.Equals("localhost", StringComparison.OrdinalIgnoreCase);

    private static bool ValidUserForTest(string user) =>
        user.Length is >= 1 and <= 32 &&
        Regex.IsMatch(user, @"\A[a-zA-Z_][a-zA-Z0-9_.-]*\z",
            RegexOptions.CultureInvariant);
}
