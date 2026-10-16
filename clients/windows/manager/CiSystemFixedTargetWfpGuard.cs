#if ENABLE_DISPOSABLE_LAB_CONTROLS
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OracleProxy.LabManager;

// R48: SYSTEM-owned, OS-backed and persistent WFP/Windows Firewall rule,
// BUT only four pinned public test resolver targets on a disposable VM.
// Not a physical all-device VPN kill switch. Does not touch default routes,
// DNS client configuration, Oracle, WireSock or UU.
internal static class CiSystemFixedTargetWfpGuard
{
    internal const string RuleName =
        "OracleProxy-R48-CI-SYSTEM-AllApps-FixedDestinations";
    private static void Stage(int id)
    {
        try
        {
            File.WriteAllText(Path.Combine(CiSystemNativeDpapiBridge.StageRoot,
                ".r48-stage"), id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        catch { /* disposable CI prints missing stage separately */ }
    }

    private const string ExactTargets =
        "1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888";

    private static bool CorrectAddresses(string? addresses)
    {
        try
        {
            if (string.IsNullOrEmpty(addresses)) return false;
            var expected = ExactTargets.Split(',')
                .Select(x => IPAddress.Parse(x).ToString())
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
            var actual = addresses.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => IPAddress.Parse(x.Trim()).ToString())
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
            return actual.Length == expected.Length &&
                actual.SequenceEqual(expected, StringComparer.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool CorrectRule(dynamic candidate)
    {
        try
        {
            object? app = candidate.ApplicationName;
            return (bool)candidate.Enabled &&
                (int)candidate.Action == 0 &&
                (int)candidate.Direction == 2 &&
                (int)candidate.Protocol == 256 &&
                (int)candidate.Profiles == int.MaxValue &&
                string.Equals((string)candidate.InterfaceTypes, "All",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals((string)candidate.LocalAddresses, "*",
                    StringComparison.Ordinal) &&
                string.IsNullOrWhiteSpace(app as string) &&
                CorrectAddresses((string)candidate.RemoteAddresses);
        }
        catch { return false; }
    }

    internal static bool IsActive()
    {
        object? policy = null;
        try
        {
            Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                ?? throw new InvalidOperationException();
            policy = Activator.CreateInstance(type);
            if (policy is null) return false;
            dynamic ruleSet = policy;
            int found = 0;
            foreach (object candidate in ruleSet.Rules)
            {
                dynamic item = candidate;
                if (!string.Equals((string)item.Name, RuleName,
                    StringComparison.OrdinalIgnoreCase)) continue;
                found++;
                if (found != 1 || !CorrectRule(item)) return false;
            }
            return found == 1;
        }
        catch { return false; }
        finally
        {
            if (policy is not null && Marshal.IsComObject(policy))
                Marshal.FinalReleaseComObject(policy);
        }
    }

    internal static void Install()
    {
        if (!OperatingSystem.IsWindows() ||
            !CiSystemDpapiKeyLease.IsSystemServiceIdentity() ||
            !CiSystemNativeDpapiBridge.Preflight())
            throw new InvalidOperationException("R48 CI SYSTEM policy gate closed");
        Stage(10);
        object? policy = null;
        object? newRule = null;
        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                ?? throw new InvalidOperationException();
            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", true)
                ?? throw new InvalidOperationException();
            policy = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException();
            Stage(20);
            dynamic guard = policy;
            foreach (object candidate in guard.Rules)
            {
                dynamic existing = candidate;
                if (string.Equals((string)existing.Name, RuleName,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        "R48 preexisting rule, do not adopt or overwrite");
            }
            Stage(30);
            newRule = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException();
            dynamic rule = newRule;
            rule.Name = RuleName;
            rule.Description = "Disposable CI only: SYSTEM four fixed targets all-apps block";
            rule.Protocol = 256;
            rule.Direction = 2;
            rule.Action = 0;
            rule.Enabled = true;
            rule.Profiles = 2147483647;
            rule.InterfaceTypes = "All";
            rule.LocalAddresses = "*";
            rule.RemoteAddresses = ExactTargets;
            Stage(40);
            // No ApplicationName assignment: all processes and executables.
            guard.Rules.Add(rule);
            Stage(50);
            // Numeric flags reveal only which expected CI rule dimensions
            // Windows COM actually accepted, never addresses or secrets.
            int matched = 0;
            try
            {
                dynamic live = guard.Rules.Item(RuleName);
                if ((bool)live.Enabled) matched |= 1;
                if ((int)live.Action == 0) matched |= 2;
                if ((int)live.Direction == 2) matched |= 4;
                if ((int)live.Protocol == 256) matched |= 8;
                if ((int)live.Profiles == int.MaxValue) matched |= 16;
                if (string.Equals((string)live.InterfaceTypes, "All",
                    StringComparison.OrdinalIgnoreCase)) matched |= 32;
                if (string.Equals((string)live.LocalAddresses, "*",
                    StringComparison.Ordinal)) matched |= 64;
                object? app = live.ApplicationName;
                if (string.IsNullOrWhiteSpace(app as string)) matched |= 128;
                string remote = (string)live.RemoteAddresses;
                if (CorrectAddresses(remote)) matched |= 256;
                // The only addresses set on this lab rule are fixed public test
                // destinations; record the COM serializer's format, strictly
                // sanitized, to diagnose a rejected (NEVER accepted) rule.
                if (remote.Length is > 0 and <= 256 &&
                    System.Text.RegularExpressions.Regex.IsMatch(remote,
                      @"^[0-9a-fA-F\.:/,; \-]+$"))
                    File.WriteAllText(Path.Combine(CiSystemNativeDpapiBridge.StageRoot,
                        ".r48-remote-diagnostic"), remote);
            }
            catch { /* fail closed with partial metric only */ }
            Stage(5000 + matched);
            if (!IsActive())
                throw new InvalidOperationException("R48 owned WFP guard not verified");
            Stage(60);
        }
        finally
        {
            if (newRule is not null && Marshal.IsComObject(newRule))
                Marshal.FinalReleaseComObject(newRule);
            if (policy is not null && Marshal.IsComObject(policy))
                Marshal.FinalReleaseComObject(policy);
        }
    }
}
#endif
