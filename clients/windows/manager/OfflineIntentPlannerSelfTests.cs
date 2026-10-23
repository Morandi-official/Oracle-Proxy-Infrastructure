using System.Text.Json;

namespace OracleProxy.LabManager;

internal static class OfflineIntentPlannerSelfTests
{
    internal static bool Run()
    {
        var planner = new OfflineIntentPlanner();
        int checks = 0;
        void Check(bool condition)
        {
            if (!condition) throw new InvalidOperationException("R4 check " + checks);
            checks++;
        }
        JsonElement Parse(string result) => JsonDocument.Parse(result).RootElement.Clone();
        string Request(string cmd, Guid? id = null) =>
            JsonSerializer.Serialize(new { protocol_version = 1,
                request_id = (id ?? Guid.NewGuid()).ToString("D"), command = cmd });
        void Safe(JsonElement reply)
        {
            Check(reply.GetProperty("offline_model_only").GetBoolean());
            Check(!reply.GetProperty("actual_wfp_enforcement").GetBoolean());
            Check(!reply.GetProperty("production_ipc_commands_enabled").GetBoolean());
            Check(!reply.GetProperty("durable_store_connected").GetBoolean());
            Check(reply.GetProperty("physical_egress_block_required").GetBoolean());
            Check(reply.GetProperty("state").GetString() != "Disabled");
        }
        try
        {
            Safe(Parse(planner.Snapshot()));
            Check(Parse(planner.Snapshot()).GetProperty("state").GetString()
                  == "UnknownFailClosed");
            string trustedEnable = Request("ExplicitEnable");
            var rejected = Parse(planner.ProcessOfflineRequest(trustedEnable, false));
            Check(!rejected.GetProperty("accepted").GetBoolean());
            Safe(rejected);
            foreach (var malformed in new[] {
                "", "{}", "[]", "null", "{", new string('z', 600),
                "{\"protocol_version\":1,\"request_id\":\"not-guid\",\"command\":\"ExplicitEnable\"}",
                "{\"protocol_version\":2,\"request_id\":\""+Guid.NewGuid().ToString("D")+"\",\"command\":\"ExplicitEnable\"}",
                "{\"protocol_version\":1,\"command\":\"ExplicitEnable\",\"request_id\":\""+Guid.NewGuid().ToString("D")+"\",\"authorized\":true}",
                "{\"protocol_version\":1,\"command\":\"ExplicitEnable\",\"command\":\"RequestExplicitDisable\",\"request_id\":\""+Guid.NewGuid().ToString("D")+"\"}",
                "{\"protocol_version\":1,\"request_id\":123,\"command\":\"ExplicitEnable\"}"
            })
            {
                var reply = Parse(planner.ProcessOfflineRequest(malformed, true));
                Check(!reply.GetProperty("accepted").GetBoolean());
                Safe(reply);
            }
            Safe(Parse(planner.ProcessOfflineRequest(Request("RequestExplicitDisable"), true)));
            Check(Parse(planner.Snapshot()).GetProperty("state").GetString()
                  == "UnknownFailClosed");
            var enabled = Parse(planner.ProcessOfflineRequest(trustedEnable, true));
            Check(enabled.GetProperty("accepted").GetBoolean());
            Check(enabled.GetProperty("state").GetString() == "Enabled");
            Check(enabled.GetProperty("revision").GetInt64() == 1);
            Safe(enabled);

            var replay = Parse(planner.ProcessOfflineRequest(trustedEnable, true));
            Check(!replay.GetProperty("accepted").GetBoolean());
            Check(replay.GetProperty("code").GetString() == "REPLAY_DENIED");
            Safe(replay);

            Check(!Parse(planner.ProcessOfflineRequest(Request("CommitOff"), true))
                    .GetProperty("accepted").GetBoolean());
            Check(!Parse(planner.ProcessOfflineRequest(Request("StartShell"), true))
                    .GetProperty("accepted").GetBoolean());
            var pending = Parse(planner.ProcessOfflineRequest(
                Request("RequestExplicitDisable"), true));
            Check(pending.GetProperty("accepted").GetBoolean());
            Check(pending.GetProperty("disable_pending").GetBoolean());
            Check(pending.GetProperty("revision").GetInt64() == 1);
            Safe(pending);
            Safe(Parse(planner.ObserveDisconnect()));
            Safe(Parse(planner.ObserveStaleHandshake()));
            Safe(Parse(planner.ObserveServiceCrash()));
            Check(Parse(planner.Snapshot()).GetProperty("disable_pending").GetBoolean());
            Check(Parse(planner.Snapshot()).GetProperty("revision").GetInt64() == 1);
            var enableAgain = Parse(planner.ProcessOfflineRequest(Request("ExplicitEnable"), true));
            Check(enableAgain.GetProperty("accepted").GetBoolean());
            Check(!enableAgain.GetProperty("disable_pending").GetBoolean());
            Check(enableAgain.GetProperty("revision").GetInt64() == 2);
            Safe(enableAgain);

            // Fresh process after crash has UNKNOWN, never inferred OFF.
            var fresh = new OfflineIntentPlanner();
            Safe(Parse(fresh.Snapshot()));
            Check(Parse(fresh.Snapshot()).GetProperty("state").GetString()
                  == "UnknownFailClosed");
            Check(checks > 100);
            Console.WriteLine("R4_OFFLINE_PASS: " + checks +
                " assertions; strict OS-authorized transition-plan frame," +
                " no implicit Off and no real service/network/WFP mutation");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R4_OFFLINE_FAIL: " + ex.GetType().Name +
                                    " check=" + checks);
            return false;
        }
    }
}
