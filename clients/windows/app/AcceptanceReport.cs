using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// R108: data minimization and evidence honesty are mandatory. This report
// NEVER attempts Internet probes, opens WFP for mutation, starts a VPN,
// invokes a shell, or changes the host or Oracle networking.
// A local service status or default route presence is NOT fail-close evidence.
internal static class AcceptanceReport
{
    internal const string NotTested = "NOT_TESTED";
    internal const string NotVerified = "NOT_VERIFIED";
    internal const string ProductionDenied = "BLOCKED_R83";
    private static readonly string[] ApprovedStatuses = {
        "Absent", "Stopped", "StartPending", "StopPending", "Running",
        "ContinuePending", "PausePending", "Paused", "Unknown"
    };

    private static string SafeServiceStatus(string value) =>
        ApprovedStatuses.Contains(value, StringComparer.Ordinal) ? value : "Unknown";

    internal static string Render(DiagnosticSnapshot local, bool managerAuthenticated,
        DateTimeOffset now)
    {
        // Prevent arbitrary OS/user/IPC input from entering a public report.
        int adapters = Math.Clamp(local.PhysicalAdapterCount, 0, 99);
        var data = new
        {
            schema_version = 1,
            report_kind = "LOCAL_READ_ONLY_PRECHECK_NOT_VPN_ATTESTATION",
            created_utc = now.ToUniversalTime().ToString("O"),
            report_privacy = "No IP, DNS server, gateway, MAC, PID, account, key, host, route target or config path",
            observed = new
            {
                physical_adapter_type_candidate_count = adapters,
                physical_candidate_ipv4_default_route_exists = local.IPv4DefaultRoute,
                physical_candidate_ipv6_default_route_exists = local.IPv6DefaultRoute,
                wiresock_driver_state = SafeServiceStatus(local.WireSockDriverState),
                wiresock_service_state = SafeServiceStatus(local.WireSockServiceState),
                wireguard_manager_state = SafeServiceStatus(local.WireGuardManagerState),
                uu_process_name_seen = local.UuServerPresent,
                expected_manager_status_pipe_authenticated = managerAuthenticated
            },
            mandatory_independent_evidence = new
            {
                upstream_signed_wireguardnt_engine_and_publisher = NotVerified,
                real_two_host_wireguard_handshake = NotTested,
                all_device_wfp_ipv4_ipv6_tcp_udp_dns = NotTested,
                physical_interface_packet_leak_capture = NotTested,
                stale_handshake_and_crash_fail_closed = NotTested,
                real_windows_reboot_prelogin_recovery = NotTested,
                explicit_off_restores_only_owned_networking = NotTested,
                real_uu_control_continuity_and_process_identity = NotTested,
                signed_installer_update_uninstaller_rollback = NotTested
            },
            product_gate = new
            {
                production_connect = ProductionDenied,
                production_disconnect = ProductionDenied,
                ga_authorized = false,
                safe_to_replace_wiresock = false
            },
            data_collection = new
            {
                public_endpoints_contacted = false,
                packets_captured = false,
                privileged_commands_executed = false,
                wfp_rules_changed = false,
                routes_or_dns_changed = false,
                vpn_or_other_services_started_or_stopped = false
            }
        };
        return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
    }

    internal static async Task<string> CollectAsync(CancellationToken token)
    {
        var local = await SanitizedDiagnostics.CollectAsync(token);
        bool trustedManager = false;
        try
        {
            var status = await ManagerStatusClient.ReadAsync(token);
            trustedManager = status.StatusPipeAuthenticated &&
                !status.MutationsAvailable &&
                status.Connected == "unverified" &&
                status.LeakProtection == "unverified";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Uninstalled/inaccessible/spoofed manager is NOT proof.
            trustedManager = false;
        }
        return Render(local, trustedManager, DateTimeOffset.UtcNow);
    }

    // Runs offline on the actual Windows hosted test, with synthetic input.
    // Verifies explicitly missing evidence stays missing, and hostile fields
    // never become report contents. No networking or actual WFP takes place.
    internal static bool SelfTest()
    {
        var source = new DiagnosticSnapshot(2, true, true,
            "Running", "Stopped", "Unknown", true, "2026-10-18T00:00:00Z");
        string report = Render(source, false,
            new DateTimeOffset(2026, 10, 18, 0, 0, 0, TimeSpan.Zero));
        using var json = JsonDocument.Parse(report);
        var root = json.RootElement;
        var evidence = root.GetProperty("mandatory_independent_evidence");
        foreach (var item in evidence.EnumerateObject())
        {
            if (item.Value.GetString() is not (NotTested or NotVerified))
                return false;
        }
        var gate = root.GetProperty("product_gate");
        if (gate.GetProperty("ga_authorized").GetBoolean() ||
            gate.GetProperty("safe_to_replace_wiresock").GetBoolean() ||
            gate.GetProperty("production_connect").GetString() != ProductionDenied)
            return false;
        var collection = root.GetProperty("data_collection");
        if (collection.EnumerateObject().Any(p => p.Value.GetBoolean()))
            return false;
        if (root.GetProperty("observed")
            .GetProperty("expected_manager_status_pipe_authenticated").GetBoolean())
            return false;
        var injected = source with
        {
            WireSockDriverState = "PRIVATE_KEY=NOT_A_STATUS",
            WireSockServiceState = "192.0.2.123"
        };
        var hostile = Render(injected, true, DateTimeOffset.UtcNow);
        if (hostile.Contains("PRIVATE_KEY", StringComparison.Ordinal) ||
            hostile.Contains("192.0.2.123", StringComparison.Ordinal))
            return false;
        using var sanitized = JsonDocument.Parse(hostile);
        return sanitized.RootElement.GetProperty("observed")
                   .GetProperty("wiresock_driver_state").GetString() == "Unknown"
               && sanitized.RootElement.GetProperty("observed")
                   .GetProperty("wiresock_service_state").GetString() == "Unknown"
               && root.GetProperty("schema_version").GetInt32() == 1;
    }
}
