#if ENABLE_DISPOSABLE_LAB_CONTROLS
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OracleProxy.LabManager;

// COM-backed Windows Firewall/WFP guard, compiled ONLY into the explicitly
// opted-in, disposable hosted CI lab manager. No production release reference.
// The target is ONE known pwsh.exe executable, NEVER all physical egress.
// No remote endpoint, user supplied path or JSON field controls this rule.
internal static class CiOnlyWfpGuard
{
    internal const string RuleName = "OracleProxy-R21-CI-SYSTEM-OnlyGuard";
    internal static string FixedProgram
    {
        get
        {
            var programFiles = Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrWhiteSpace(programFiles))
                throw new InvalidOperationException("Unresolved ProgramFiles");
            return Path.Combine(programFiles, "PowerShell", "7", "pwsh.exe");
        }
    }

    // Query the CURRENT OS-owned rule; caller JSON/environment cannot assert
    // readiness. Any ambiguous/missing/mutated policy returns false.
    internal static bool IsActive()
    {
        if (!OperatingSystem.IsWindows() || !AdminLabControl.IsDisposableCiLab())
            return false;
        object? policyObject = null;
        try
        {
            Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                ?? throw new InvalidOperationException("Windows Firewall unavailable");
            policyObject = Activator.CreateInstance(type);
            if (policyObject == null) return false;
            dynamic policy = policyObject;
            int matches = 0;
            foreach (object candidate in policy.Rules)
            {
                dynamic live = candidate;
                if (!string.Equals((string)live.Name, RuleName,
                    StringComparison.OrdinalIgnoreCase)) continue;
                matches++;
                if (matches != 1 ||
                    !(bool)live.Enabled || (int)live.Action != 0 ||
                    (int)live.Protocol != 256 || (int)live.Direction != 2 ||
                    !string.Equals((string)live.ApplicationName, FixedProgram,
                        StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return matches == 1;
        }
        catch { return false; }
        finally
        {
            if (policyObject != null && Marshal.IsComObject(policyObject))
                Marshal.ReleaseComObject(policyObject);
        }
    }

    internal static void Install()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0 ||
            !AdminLabControl.IsDisposableCiLab())
            throw new InvalidOperationException("R21 CI SYSTEM gate closed");

        string program = FixedProgram;
        var file = new FileInfo(program);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("R21 fixed probe executable unavailable");

        object? policyObject = null;
        object? ruleObject = null;
        try
        {
            Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                ?? throw new InvalidOperationException("Windows Firewall unavailable");
            Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", true)
                ?? throw new InvalidOperationException("Firewall rule COM unavailable");
            policyObject = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException("Cannot open Windows Firewall");
            dynamic policy = policyObject;
            // Enumerate existing rules rather than relying on COM's
            // platform-dependent not-found HRESULT. Any enumeration failure
            // aborts installation; no existing named rule is overwritten.
            foreach (object candidate in policy.Rules)
            {
                dynamic existing = candidate;
                string existingName = (string)existing.Name;
                if (string.Equals(existingName, RuleName,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        "Existing R21 guard must not be replaced");
            }

            ruleObject = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException("Cannot allocate Windows Firewall rule");
            dynamic rule = ruleObject;
            rule.Name = RuleName;
            rule.Description = "Disposable CI only: SYSTEM persists a pwsh-only outbound guard";
            rule.ApplicationName = program;
            rule.Protocol = 256; // NET_FW_IP_PROTOCOL_ANY, includes UDP and TCP
            rule.Direction = 2;  // NET_FW_RULE_DIR_OUT
            rule.Action = 0;     // NET_FW_ACTION_BLOCK
            rule.Profiles = 2147483647; // NET_FW_PROFILE2_ALL
            rule.Enabled = true;
            policy.Rules.Add(rule);
            // Verify persisted metadata. External CI does packet-level proof.
            dynamic live = policy.Rules.Item(RuleName);
            if (!(bool)live.Enabled || (int)live.Action != 0 ||
                (int)live.Protocol != 256 || (int)live.Direction != 2 ||
                !string.Equals((string)live.ApplicationName, program,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("R21 guard activation not verified");
        }
        finally
        {
            if (ruleObject != null && Marshal.IsComObject(ruleObject))
                Marshal.ReleaseComObject(ruleObject);
            if (policyObject != null && Marshal.IsComObject(policyObject))
                Marshal.ReleaseComObject(policyObject);
        }
    }
}
#endif
