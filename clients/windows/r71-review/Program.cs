using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;

namespace OracleProxy.R71.ReadOnlyReview;

// R71: standalone OBSERVATION ONLY. No WireGuard, SCM write, DNS/routes,
// named-pipe control, shell, network probing, filesystem writing or key access.
internal static class Program
{
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    // Explicitly always false: a local observation is never the missing
    // independent full-device / UU / signed-driver authorization.
    private static bool NativeVpnTrialAuthorized => false;

    private static bool ServiceRunning(string name)
    {
        try
        {
            using var service = new ServiceController(name);
            return service.Status == ServiceControllerStatus.Running;
        }
        catch { return false; } // Unreadable is unknown, never green.
    }

    private static object CollectReadOnly()
    {
        bool platform = OperatingSystem.IsWindows() &&
            RuntimeInformation.ProcessArchitecture == Architecture.X64;
        if (!platform)
            throw new PlatformNotSupportedException();

        bool elevated = false, activeConsoleSession = false;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            elevated = identity.IsAuthenticated &&
                new WindowsPrincipal(identity).IsInRole(
                    WindowsBuiltInRole.Administrator);
            uint console = WTSGetActiveConsoleSessionId();
            using Process process = Process.GetCurrentProcess();
            activeConsoleSession = console != uint.MaxValue &&
                process.SessionId > 0 &&
                (uint)process.SessionId == console;
        }
        catch
        {
            // A failed identity query must not be used as evidence of safety.
        }

        int upEthernetOrWifi = 0;
        bool adapterEnumerationCompleted = false;
        try
        {
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus == OperationalStatus.Up &&
                    item.NetworkInterfaceType is NetworkInterfaceType.Ethernet or
                        NetworkInterfaceType.Wireless80211)
                {
                    upEthernetOrWifi++;
                    if (upEthernetOrWifi > 128) throw new InvalidOperationException();
                }
            }
            adapterEnumerationCompleted = true;
        }
        catch { upEthernetOrWifi = 0; }

        // An active-console session does NOT prove somebody can physically
        // restore a broken system. No remote control process-name heuristics.
        return new
        {
            schema_version = 1,
            mode = "R71_READ_ONLY_REVIEW_NO_VPN",
            os_is_windows_x64 = platform,
            running_as_elevated_admin = elevated,
            session_matches_active_console = activeConsoleSession,
            physical_out_of_band_recovery_verified = false,
            adapter_enumeration_completed = adapterEnumerationCompleted,
            up_ethernet_wifi_candidate_count = upEthernetOrWifi,
            bfe_service_running = ServiceRunning("BFE"),
            windows_firewall_service_running = ServiceRunning("MpsSvc"),
            native_wireguard_public_internet_verified = false,
            windows_wfp_all_device_verified = false,
            ipv4_ipv6_dns_packet_leak_proof_verified = false,
            uu_remote_continuity_verified = false,
            signed_install_and_rollback_verified = false,
            native_vpn_trial_authorized = NativeVpnTrialAuthorized,
            production_replacement_approved = false,
            network_mutation_performed = false,
            secrets_or_addresses_collected = false
        };
    }

    private static int SelfTest()
    {
        try
        {
            if (NativeVpnTrialAuthorized || !OperatingSystem.IsWindows())
                return 1;
            // The public CLI has exactly two entrypoints. Neither can
            // construct the production manager, invoke WireGuard, or
            // authorize connection even if the environment mimics CI.
            string[] forbidden = {
                "--connect", "--disconnect", "--install", "--service",
                "--manager-service", "--ci-lab-start-a", "--ci-wfp-guard",
                "--public-endpoint", "--production-enable", "--rollback",
                "--allow-default-route", "--review-only --connect"
            };
            foreach (string command in forbidden)
                if (CommandIsAllowed(new[] { command }))
                    return 1;
            if (CommandIsAllowed(Array.Empty<string>()) ||
                CommandIsAllowed(new[] { "--review-only", "--connect" }) ||
                !CommandIsAllowed(new[] { "--review-only" }) ||
                !CommandIsAllowed(new[] { "--self-test" }))
                return 1;
            Console.WriteLine("R71_READONLY_CLI_NO_MUTATING_COMMAND_PASS");
            return 0;
        }
        catch { return 1; }
    }

    private static bool CommandIsAllowed(string[] args) =>
        args.Length == 1 &&
        (args[0] == "--review-only" || args[0] == "--self-test");

    private static int Main(string[] args)
    {
        // Refuse before reading any OS state for unexpected commands.
        if (!CommandIsAllowed(args)) return 2;
        if (!OperatingSystem.IsWindows()) return 3;
        if (args[0] == "--self-test") return SelfTest();
        try
        {
            // Never publish host names, account identity, IPs, peer keys,
            // remote endpoints, interface indices or process identities.
            Console.WriteLine(JsonSerializer.Serialize(CollectReadOnly()));
            return 0; // Observation succeeded; NOT an authorization signal.
        }
        catch
        {
            Console.Error.WriteLine("R71_READONLY_REPORT_UNAVAILABLE");
            return 3;
        }
    }
}
