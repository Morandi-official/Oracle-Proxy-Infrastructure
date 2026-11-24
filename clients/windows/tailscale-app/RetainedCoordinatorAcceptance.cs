#if RETAINED_COORDINATOR_ACCEPTANCE
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OracleProxy.Tailscale;

internal static partial class LiveAcceptance
{
    private const string TraceIPv6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace";

    internal static async Task<int> RunRetainedCoordinator(string output)
    {
        string? username = Environment.GetEnvironmentVariable(Username);
        string? password = Environment.GetEnvironmentVariable(Password);
        Environment.SetEnvironmentVariable(Username, null);
        Environment.SetEnvironmentVariable(Password, null);
        string phase = "DIRECT_BASELINE";
        var pairs = new List<object>();
        var report = new Dictionary<string, object?>
        {
            ["experiment"] = "retained-coordinator",
            ["pairs"] = pairs,
        };
        using var account = new AccountClient();
        using var web = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            PooledConnectionLifetime = TimeSpan.Zero,
        }) { Timeout = TimeSpan.FromSeconds(5), MaxResponseContentBufferSize = 8192 };
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        string? session = null;
        int result = 1;
        try
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
                throw new IOException("ACCEPTANCE_CREDENTIALS_MISSING");

            var direct = await ObserveIPv4(web, timeout.Token);
            var directV6 = await ObserveOptionalIPv6(web, timeout.Token);
            report["direct_ipv6_available"] = directV6 is not null;

            phase = "LOGIN";
            string state = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, "retained-state");
            session = await account.Login(username, password, ClientConnection.Device(state), timeout.Token);
            password = null;

            phase = "INITIAL_ENROLLMENT";
            var coldTimer = Stopwatch.StartNew();
            var (firstDaemon, firstProfile) = await ClientConnection.Open(account, session, state, timeout.Token,
                stage => phase = "INITIAL_" + stage);
            await using (firstDaemon)
            {
                report["initial_connect_ms"] = coldTimer.ElapsedMilliseconds;
                report["account_rate_limited"] = firstProfile.RateLimited;
                var expected = IPAddress.Parse(firstProfile.IPv4);
                if (expected.Equals(direct)) throw new IOException("ACCEPTANCE_BASELINE_EQUALS_EXIT");
                await RequireIPv4(web, expected, timeout.Token);
            }

            for (int trial = 1; trial <= 3; trial++)
            {
                report["current_trial"] = trial;
                phase = "DIRECT_AFTER_FULL_STOP";
                await RequireDirect(web, direct, directV6, null, timeout.Token);

                phase = "FULL_RESTART";
                var startedAt = DateTimeOffset.UtcNow;
                var timer = Stopwatch.StartNew();
                var fullTiming = new ConcurrentDictionary<string, long>();
                var (daemon, profile) = await ClientConnection.Open(account, session, state, timeout.Token,
                    step => phase = "FULL_RESTART_" + step, (step, elapsed) => fullTiming[step] = elapsed);
                await using (daemon)
                {
                    long fullMillis = timer.ElapsedMilliseconds;
                    RequireSameExit(firstProfile, profile);
                    var expected = IPAddress.Parse(profile.IPv4);
                    await RequireIPv4(web, expected, timeout.Token);
                    string fullTransport = await daemon.Control.ReadExitTransport(profile.NodeId, timeout.Token);

                    phase = "DIRECT_WITH_RETAINED_COORDINATOR";
                    var directTimer = Stopwatch.StartNew();
                    await daemon.Control.ClearExitForProbe(timeout.Token);
                    await RequireDirect(web, direct, directV6, daemon.Control, timeout.Token);
                    long clearMillis = directTimer.ElapsedMilliseconds;

                    phase = "RETAINED_ACCOUNT_PROFILE";
                    var retainedStartedAt = DateTimeOffset.UtcNow;
                    var retainedTimer = Stopwatch.StartNew();
                    var retainedTiming = new ConcurrentDictionary<string, long>();
                    var fresh = await account.Profile(session, false, timeout.Token);
                    retainedTiming["account_ready"] = retainedTimer.ElapsedMilliseconds;
                    RequireSameExit(profile, fresh);

                    phase = "RETAINED_SELECT_EXIT";
                    await daemon.Control.SelectExitNode(fresh.NodeId, timeout.Token);
                    retainedTiming["exit_selected"] = retainedTimer.ElapsedMilliseconds;
                    phase = "RETAINED_VERIFY_EXIT";
                    await ExitCheck.Verify(daemon, fresh, timeout.Token, step => retainedTiming[step] = retainedTimer.ElapsedMilliseconds);
                    long retainedMillis = retainedTimer.ElapsedMilliseconds;
                    await RequireIPv4(web, expected, timeout.Token);
                    string retainedTransport = await daemon.Control.ReadExitTransport(fresh.NodeId, timeout.Token);

                    pairs.Add(new
                    {
                        trial,
                        full_restart = new { started_at = startedAt, connect_ms = fullMillis, transport = fullTransport, milestones_ms = fullTiming },
                        retained_coordinator = new { started_at = retainedStartedAt, connect_ms = retainedMillis, transport = retainedTransport, milestones_ms = retainedTiming },
                        clear_exit_and_verify_direct_ms = clearMillis,
                        difference_ms = fullMillis - retainedMillis,
                    });
                }
            }

            phase = "DIRECT_AFTER_FINAL_STOP";
            await RequireDirect(web, direct, directV6, null, timeout.Token);
            report.Remove("current_trial");
            result = 0;
        }
        catch (Exception error)
        {
            report["phase"] = phase;
            report["error"] = error is IOException && Regex.IsMatch(error.Message, @"\A[A-Z0-9_]{1,80}\z")
                ? error.Message : error.GetType().Name;
        }
        finally
        {
            if (session is not null)
            {
                using var release = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                try { await account.Release(session, release.Token); }
                catch
                {
                    report["device_release_failed"] = true;
                    result = 1;
                }
            }
            report["accepted"] = result == 0;
            File.WriteAllText(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        }
        return result;
    }

    private static void RequireSameExit(ExitProfile previous, ExitProfile fresh)
    {
        if (fresh.Key is not null || previous.Coordinator != fresh.Coordinator || previous.NodeId != fresh.NodeId ||
            !IPAddress.Parse(previous.IPv4).Equals(IPAddress.Parse(fresh.IPv4)) ||
            !IPAddress.Parse(previous.IPv6).Equals(IPAddress.Parse(fresh.IPv6)))
            throw new IOException("RETAINED_PROBE_AUTHORIZED_EXIT_CHANGED");
    }

    private static async Task RequireDirect(HttpClient web, IPAddress direct, IPAddress? directV6,
        LocalControl? retained, CancellationToken cancel)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            if (retained is not null)
            {
                while (true)
                {
                    var state = await retained.ReadState(deadline.Token);
                    if (state.State == "Running" && state.HasNodeKey && state.ExitId == "")
                        break;
                    await Task.Delay(50, deadline.Token);
                }
            }
            while (true)
            {
                try
                {
                    if ((await ObserveIPv4(web, deadline.Token)).Equals(direct) &&
                        Equals(await ObserveOptionalIPv6(web, deadline.Token), directV6))
                        break;
                }
                catch (HttpRequestException) { }
                await Task.Delay(100, deadline.Token);
            }
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            throw new IOException("RETAINED_PROBE_DIRECT_ROUTE_NOT_RESTORED");
        }
    }

    private static async Task<IPAddress?> ObserveOptionalIPv6(HttpClient web, CancellationToken cancel)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var address = await ObserveIP(web, TraceIPv6, deadline.Token);
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                throw new IOException("RETAINED_PROBE_DIRECT_IPV6_WRONG_FAMILY");
            return address;
        }
        catch (HttpRequestException) { return null; }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested) { return null; }
    }
}
#endif
