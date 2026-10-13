using System.Text.Json;

namespace OracleProxy.LabManager;

internal static class AdminLabControlSelfTests
{
    internal static async Task<bool> RunAsync()
    {
        int checks = 0;
        try
        {
            void Check(bool test)
            {
                if (!test) throw new InvalidOperationException("admin lab test #" + checks);
                checks++;
            }
            static string Frame(string command, Guid? id = null) =>
                JsonSerializer.Serialize(new {
                    protocol_version = 1,
                    request_id = (id ?? Guid.NewGuid()).ToString("D"),
                    command
                });
            bool fakeDispatched = false;
            bool Fake(LabControlAction action)
            {
                fakeDispatched = true;
                return action is LabControlAction.StartA or LabControlAction.StopA;
            }
            var rules = new AdminLabControl();
            var start = Frame("StartLabPeerA");
            Check(rules.Process(start, false, true, Fake).Contains("ADMIN_OS_TOKEN_REQUIRED"));
            Check(!fakeDispatched);
            Check(rules.Process(start, true, false, Fake).Contains("ISOLATED_LAB_GATE_CLOSED"));
            Check(!fakeDispatched);
            Check(rules.Process(start, true, true, Fake).Contains("LAB_SERVICE_CHANGED"));
            Check(fakeDispatched);
            Check(rules.Process(start, true, true, Fake).Contains("REPLAYED_REQUEST"));
            foreach (var forbidden in new[] {
                "EnableVpn", "DisableVpn", "InstallDriver", "StopWireSock",
                "StopService", "SetFirewall", "SetConfig", "ConnectOracle"
            })
            {
                fakeDispatched = false;
                Check(rules.Process(Frame(forbidden), true, true, Fake)
                    .Contains("COMMAND_NOT_IN_ALLOWLIST"));
                Check(!fakeDispatched);
            }
            foreach (string malformed in new[] {
                "", "{}", "[]", "null", "{",
                "{\"protocol_version\":1,\"request_id\":\"x\",\"command\":\"StartLabPeerA\"}",
                "{\"protocol_version\":1,\"request_id\":\"x\",\"command\":\"StartLabPeerA\",\"service\":\"WireSock\"}",
                "{\"protocol_version\":1,\"request_id\":\"x\",\"command\":\"StartLabPeerA\",\"command\":\"StopLabPeerA\"}",
                new string('x', 1024)
            })
            {
                fakeDispatched = false;
                string reply = rules.Process(malformed, true, true, Fake);
                Check(!JsonDocument.Parse(reply).RootElement.GetProperty("ok").GetBoolean());
                Check(!fakeDispatched);
            }

            // Exercise a real Windows named pipe and OS CurrentUserOnly policy,
            // but dispatch is a fake callback: zero SCM/network mutations.
            string pipeName = "OracleProxyAdminLab." + Guid.NewGuid().ToString("N");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var pipeController = new AdminLabControl();
            Task worker = Task.Run(() => pipeController.ServeAsync(
                pipeName, sameUserTest: true, Fake, timeout.Token, 2));
            var allowed = await LabPipe.ClientRequestAsync(
                pipeName, Frame("StartLabPeerA"), timeout.Token);
            Check(JsonDocument.Parse(allowed).RootElement.GetProperty("ok").GetBoolean());
            var refused = await LabPipe.ClientRequestAsync(
                pipeName, Frame("DisconnectProductionVPN"), timeout.Token);
            Check(!JsonDocument.Parse(refused).RootElement.GetProperty("ok").GetBoolean());
            await worker.WaitAsync(TimeSpan.FromSeconds(5));
            Check(checks > 30);
            Console.WriteLine("PASS: admin-only isolated lab pipe rejects unverified and arbitrary VPN commands");
            return true;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("FAIL: isolated lab control " + e.GetType().Name +
                                    " at assertion " + checks);
            return false;
        }
    }
}
