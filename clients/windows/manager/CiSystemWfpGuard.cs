using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace OracleProxy.LabManager;

// Lab-only: SYSTEM service itself changes Windows Firewall (WFP backed).
// No OS changes in default assemblies; no configurable rule/path/command.
internal static class CiSystemWfpGuard
{
    internal const string RuleName = "OracleProxy-R21-CI-SystemOwner-v1";
    private const int Outbound = 2;
    private const int Block = 0;
    private const int AnyProtocol = 256;
    private const int AllProfiles = 7;

    private static string FixedProgram()
    {
        string? root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(root)) throw new InvalidOperationException();
        string program = Path.Combine(root, "PowerShell", "7", "pwsh.exe");
        var file = new FileInfo(program);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length < 100_000)
            throw new InvalidOperationException("R21 targeted CI process missing");
        return Path.GetFullPath(program);
    }

    private static bool IsAuthorized()
    {
        if (!AdminLabControl.IsDisposableCiLab()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem && Process.GetCurrentProcess().SessionId == 0;
    }

    private static dynamic OpenPolicy()
    {
        Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException();
    }

    private static dynamic OpenRule()
    {
        Type type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException();
    }

    private static object? GetByName(dynamic rules)
    {
        try { return rules.Item(RuleName); }
        catch (COMException e) when ((uint)e.HResult is 0x80070002 or 0x80070490) { return null; }
    }

    private static bool SameRule(dynamic entry, string program) =>
        entry != null &&
        string.Equals((string)entry.Name, RuleName, StringComparison.Ordinal) &&
        string.Equals((string)entry.ApplicationName, program,
            StringComparison.OrdinalIgnoreCase) &&
        (int)entry.Direction == Outbound &&
        (int)entry.Action == Block &&
        (int)entry.Protocol == AnyProtocol &&
        (int)entry.Profiles == AllProfiles &&
        (bool)entry.Enabled &&
        string.Equals((string)entry.RemoteAddresses, "*", StringComparison.Ordinal);

    internal static bool Install()
    {
        if (!IsAuthorized()) return false;
        object? policy = null, item = null;
        try
        {
            string program = FixedProgram();
            dynamic fwPolicy = OpenPolicy(); policy = fwPolicy;
            dynamic rules = fwPolicy.Rules;
            // Never change an existing policy, even with the same name.
            if (GetByName(rules) is not null) return false;
            dynamic rule = OpenRule(); item = rule;
            rule.Name = RuleName;
            rule.Description = "DISPOSABLE GITHUB RUNNER TEST: one PowerShell executable; NOT VPN kill switch";
            rule.ApplicationName = program;
            rule.Direction = Outbound;
            rule.Action = Block;
            rule.Protocol = AnyProtocol;
            rule.Profiles = AllProfiles;
            rule.RemoteAddresses = "*";
            rule.Enabled = true;
            rules.Add(rule);
            object? readBack = GetByName(rules);
            return readBack is not null && SameRule((dynamic)readBack, program);
        }
        catch { return false; }
        finally
        {
            if (item is not null && Marshal.IsComObject(item)) Marshal.FinalReleaseComObject(item);
            if (policy is not null && Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
        }
    }

    internal static bool Verify()
    {
        if (!IsAuthorized()) return false;
        object? policy = null;
        try
        {
            string program = FixedProgram();
            dynamic p = OpenPolicy(); policy = p;
            object? rule = GetByName(p.Rules);
            return rule is not null && SameRule((dynamic)rule, program);
        }
        catch { return false; }
        finally
        {
            if (policy is not null && Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
        }
    }

    internal static bool Remove()
    {
        if (!IsAuthorized()) return false;
        object? policy = null;
        try
        {
            string program = FixedProgram();
            dynamic p = OpenPolicy(); policy = p;
            object? rule = GetByName(p.Rules);
            // Refuse deletion of any preexisting/different rule.
            if (rule is null || !SameRule((dynamic)rule, program)) return false;
            p.Rules.Remove(RuleName);
            return GetByName(p.Rules) is null;
        }
        catch { return false; }
        finally
        {
            if (policy is not null && Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
        }
    }
}
