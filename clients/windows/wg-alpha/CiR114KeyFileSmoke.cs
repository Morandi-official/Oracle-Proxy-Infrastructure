using System.Security.Cryptography;

namespace OracleProxy.WgAlpha;

// Compile-time excluded from released GUI. On the CI runner this creates only
// local, synthetic X25519 keys in RUNNER_TEMP, then deletes exactly them.
internal static class CiR114KeyFileSmoke
{
    internal static int Run()
    {
        if(!OperatingSystem.IsWindows() ||
           Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" ||
           Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" ||
           Environment.GetEnvironmentVariable("RUNNER_OS")!="Windows" ||
           Environment.GetEnvironmentVariable("GITHUB_HEAD_REF")!=
                "test/r114-integrated-offline-wireguard-keygen-20261019" ||
           Environment.GetEnvironmentVariable("ORACLE_R114_EXPLICIT_CI")!="CI_ONLY")
            return 3;
        string? temp=Environment.GetEnvironmentVariable("RUNNER_TEMP");
        if(string.IsNullOrEmpty(temp)||!Directory.Exists(temp))return 3;
        string? root=null;
        try
        {
            if(!LocalWireGuardKeys.SelfTest())return 4;
            var first=LocalWireGuardKeys.Create(temp);
            root=first.DirectoryPath;
            if(!LocalWireGuardKeys.CiReadBackAndValidate(first))
                return 5;
            if(EmbeddedWireGuardBridge.ReadServiceState()!="Absent")
                return 6;
            // Ensures no existing key material was overwritten: each operation
            // yields a different directory. Do NOT expose keys or paths.
            var second=LocalWireGuardKeys.Create(temp);
            try
            {
                if(first.DirectoryPath.Equals(second.DirectoryPath,
                        StringComparison.OrdinalIgnoreCase) ||
                    !LocalWireGuardKeys.CiReadBackAndValidate(second))
                    return 7;
            }
            finally { RemoveExactCITemp(second.DirectoryPath,temp); }
            return 0;
        }
        catch{return 8;}
        finally
        {
            if(root!=null)RemoveExactCITemp(root,temp);
        }
    }

    private static void RemoveExactCITemp(string root,string parent)
    {
        // Narrow CI-only cleanup: no recursive deletion, no reparse points,
        // no deletion outside the GitHub runner temporary directory.
        if(Path.GetDirectoryName(root)!=parent ||
           !Path.GetFileName(root).StartsWith("OracleProxyAlphaKeys-",
               StringComparison.Ordinal) ||
           Directory.GetDirectories(root).Length!=0)
            return;
        string[] expected={"OracleProxyAlphaTest.privatekey",
            "OracleProxyAlphaTest.publickey"};
        var actual=Directory.GetFiles(root).Select(Path.GetFileName)
            .OrderBy(x=>x).ToArray();
        if(!actual.SequenceEqual(expected.OrderBy(x=>x),
            StringComparer.OrdinalIgnoreCase))return;
        foreach(var name in expected)
        {
            string f=Path.Combine(root,name);
            if(new FileInfo(f).Attributes.HasFlag(FileAttributes.ReparsePoint))
                return;
        }
        foreach(var name in expected)File.Delete(Path.Combine(root,name));
        Directory.Delete(root,false);
    }
}
