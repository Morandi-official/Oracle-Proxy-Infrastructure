using System.Text.Json;

namespace OracleProxy.LabManager;

internal static class SafeControlGateSelfTests
{
    internal static bool Run()
    {
        try
        {
            var gate = new SafeControlGate();
            var checks = 0;
            void Check(bool value)
            {
                if (!value) throw new InvalidOperationException("control check " + checks);
                checks++;
            }
            string Request(string command = "RequestConnect", string profile =
                SafeControlGate.FixedProfile, Guid? id = null) =>
                JsonSerializer.Serialize(new {
                    protocol_version = 1,
                    request_id = (id ?? Guid.NewGuid()).ToString("D"),
                    command, profile
                });
            JsonElement Eval(string? raw, bool admin = true)
            {
                using var doc = JsonDocument.Parse(gate.Evaluate(raw, admin));
                var root = doc.RootElement.Clone();
                Check(!root.GetProperty("ok").GetBoolean());
                Check(!root.GetProperty("network_operation_performed").GetBoolean());
                Check(!root.GetProperty("native_tunnel_control_enabled").GetBoolean());
                Check(!root.GetProperty("actual_wfp_enforcement_verified").GetBoolean());
                Check(!root.GetProperty("explicit_disconnect_committed").GetBoolean());
                return root;
            }

            string connect = Request();
            Check(Eval(connect, false).GetProperty("code").GetString() ==
                "ELEVATED_OS_ADMIN_REQUIRED");
            Check(Eval(connect).GetProperty("code").GetString() ==
                "WFP_FAIL_CLOSED_NOT_IMPLEMENTED");
            Check(Eval(connect).GetProperty("code").GetString() == "REPLAY_DENIED");
            Check(Eval(Request("RequestExplicitDisconnect")).GetProperty("code")
                .GetString() == "WFP_FAIL_CLOSED_NOT_IMPLEMENTED");
            foreach (var raw in new[] {
                "", "null", "{}", "[]", "{", new string('x', 513),
                "{\"protocol_version\":1,\"request_id\":\"x\",\"command\":\"RequestConnect\",\"profile\":\"oracle-proxy-main\"}",
                "{\"protocol_version\":1,\"request_id\":\""+Guid.NewGuid().ToString("D")+"\",\"command\":\"RequestConnect\",\"profile\":\"oracle-proxy-main\",\"os_admin\":true}",
                "{\"protocol_version\":1,\"request_id\":\""+Guid.NewGuid().ToString("D")+"\",\"command\":\"RequestConnect\",\"command\":\"RequestExplicitDisconnect\",\"profile\":\"oracle-proxy-main\"}"
            })
                Check(Eval(raw).GetProperty("code").GetString() !=
                    "WFP_FAIL_CLOSED_NOT_IMPLEMENTED");

            foreach (var cmd in new[] { "RunShell", "InstallDriver", "StartService",
                "SetConfig", "DisconnectTunnel", "EnableVpn", "CommitOff" })
                Check(Eval(Request(cmd)).GetProperty("code").GetString() ==
                    "COMMAND_NOT_ALLOWLISTED");
            foreach (var profile in new[] {"../etc", "", "WireGuardTunnel$lab-peer-a",
                "oracle-proxy-main2", "C:\\temp\\key.conf"})
                Check(Eval(Request(profile: profile)).GetProperty("code")
                    .GetString() == "PROFILE_NOT_ALLOWLISTED");

            for (var i = 0; i < 126; i++)
                Check(Eval(Request()).GetProperty("code").GetString() ==
                    "WFP_FAIL_CLOSED_NOT_IMPLEMENTED");
            Check(Eval(Request()).GetProperty("code").GetString() ==
                "REPLAY_CACHE_FULL");
            Console.WriteLine("R14_CONTROL_GATE_PASS: " + checks +
                " fail-closed assertions, no OS mutation");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R14_CONTROL_GATE_FAIL: " + ex.GetType().Name);
            return false;
        }
    }
}
