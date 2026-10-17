using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace OracleProxy.WireGuardHost;

// R80: exact allowlist enforced in the actual privileged service startup
// before LoadLibrary. Only existing two disposable localhost dual-stack lab
// profiles, NOT a production/public-peer policy or a new service entrypoint.
internal static class NativeLabInnerScopeGate
{
    internal static void Require(string file, string profile)
    {
        if (profile == "lab-only") return; // older single-profile ABI lab
        if (profile is not ("lab-peer-a" or "lab-peer-b"))
            throw new InvalidOperationException("Unknown native test profile");

        var info = new FileInfo(file);
        if (!info.Exists || info.Length is < 1 or > 1024 ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Unsupported native test config");
        string text = File.ReadAllText(file, Encoding.UTF8);
        if (!AcceptExactText(text, profile))
            throw new InvalidOperationException("Native test profile out of scope");
    }

    internal static bool AcceptExactText(string? text, string profile)
    {
        if (profile is not ("lab-peer-a" or "lab-peer-b") ||
            string.IsNullOrEmpty(text) || text.Length > 1024 ||
            !text.EndsWith('\n') || text.Contains('\r') ||
            text.Any(c => (c < 32 && c != '\n') || c > 126))
            return false;
        string[] lines = text.Split('\n');
        if (lines.Length != 11 || lines[^1] != "" ||
            lines[0] != "[Interface]" || lines[4] != "" ||
            lines[5] != "[Peer]" || lines[9] != "PersistentKeepalive = 1")
            return false;
        bool isA = profile == "lab-peer-a";
        if (lines[2] != (isA
                ? "Address = 10.249.129.1/32, fd42:14::1/128"
                : "Address = 10.249.129.2/32, fd42:14::2/128") ||
            lines[3] != (isA ? "ListenPort = 52741" : "ListenPort = 52742") ||
            lines[7] != (isA
                ? "AllowedIPs = 10.249.129.2/32, fd42:14::2/128"
                : "AllowedIPs = 10.249.129.1/32, fd42:14::1/128") ||
            lines[8] != (isA
                ? "Endpoint = 127.0.0.1:52742"
                : "Endpoint = 127.0.0.1:52741"))
            return false;

        return KeyLine(lines[1], "PrivateKey = ") &&
               KeyLine(lines[6], "PublicKey = ") &&
               !string.Equals(lines[1][13..], lines[6][12..],
                   StringComparison.Ordinal);
    }

    private static bool KeyLine(string line, string prefix)
    {
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
            return false;
        string text = line[prefix.Length..];
        if (text.Length != 44 || !text.EndsWith('=')) return false;
        byte[]? raw = null;
        try
        {
            raw = Convert.FromBase64String(text);
            return raw.Length == 32 && raw.Any(n => n != 0) &&
                   Convert.ToBase64String(raw) == text;
        }
        catch (FormatException) { return false; }
        finally
        {
            if (raw != null) CryptographicOperations.ZeroMemory(raw);
        }
    }

    internal static int TestCiOwnedFiles()
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows" ||
            Environment.GetEnvironmentVariable("ORACLE_R80") != "CI_ONLY")
            return 3;
        try
        {
            foreach (string profile in new[] { "lab-peer-a", "lab-peer-b" })
                Require(EngineBundle.FixedConfigPath(profile), profile);
            Console.WriteLine("R80_ACTUAL_NATIVE_HOST_LOCALHOST_NARROW_SCOPE_PASS");
            Console.WriteLine("R80_PRODUCTION_CONNECTION_ALLOWED=false");
            return 0;
        }
        catch { return 3; }
    }

    internal static int SelfTest()
    {
        if (Environment.GetEnvironmentVariable("ORACLE_R80") != "CI_ONLY" ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
            return 3;
        string a = Convert.ToBase64String(Enumerable.Range(1,32).Select(n=>(byte)n).ToArray());
        string b = Convert.ToBase64String(Enumerable.Range(33,32).Select(n=>(byte)n).ToArray());
        foreach (var entry in new[] { ("lab-peer-a",true),("lab-peer-b",false) })
        {
            bool first=entry.Item2;
            string cfg="[Interface]\nPrivateKey = "+(first?a:b)+"\n"+
                (first ? "Address = 10.249.129.1/32, fd42:14::1/128\nListenPort = 52741\n"
                       : "Address = 10.249.129.2/32, fd42:14::2/128\nListenPort = 52742\n")+
                "\n[Peer]\nPublicKey = "+(first?b:a)+"\n"+
                (first ? "AllowedIPs = 10.249.129.2/32, fd42:14::2/128\nEndpoint = 127.0.0.1:52742\n"
                       : "AllowedIPs = 10.249.129.1/32, fd42:14::1/128\nEndpoint = 127.0.0.1:52741\n")+
                "PersistentKeepalive = 1\n";
            if (!AcceptExactText(cfg,entry.Item1)) return 1;
            string[] bad={
                cfg.Replace("AllowedIPs = ", "AllowedIPs = 0.0.0.0/0, ::/0, "),
                cfg.Replace("fd42:14::", "fd42:15::"),
                cfg.Replace("PersistentKeepalive = 1","DNS = 1.1.1.1"),
                cfg + "PostUp = cmd.exe\n",
                cfg + "[Peer]\n",
                cfg.Replace("127.0.0.1:","8.8.8.8:"),
                cfg.Replace("ListenPort = ","Table = auto\nListenPort = "),
                cfg.Replace("\n","\r\n"),
                cfg.TrimEnd('\n'),
                cfg.Replace("PublicKey = ","PublicKey = broken"),
                cfg.Replace("Address = ","Address = 0.0.0.0/0, "),
            };
            if (bad.Any(x=>AcceptExactText(x,entry.Item1))) return 1;
            if (AcceptExactText(cfg,first?"lab-peer-b":"lab-peer-a")) return 1;
        }
        Console.WriteLine("R80_NATIVE_PRE_DLL_SCOPE_NEGATIVE_TESTS_PASS");
        return 0;
    }
}
