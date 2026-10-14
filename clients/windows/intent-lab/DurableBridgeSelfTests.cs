using System.Security.Cryptography;
using System.Text.Json;

namespace OracleProxy.IntentLab;

internal static class DurableBridgeSelfTests
{
    internal static bool Run()
    {
        int count = 0;
        string root = Path.Combine(Path.GetTempPath(),
            "oracle-r12-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string file = Path.Combine(root, "intent.protected");
        try
        {
            void Check(bool condition)
            {
                if (!condition) throw new InvalidOperationException("R12 case " + count);
                count++;
            }
            static JsonElement Parse(string message) =>
                JsonDocument.Parse(message).RootElement.Clone();
            static string Frame(string command, Guid? id = null) =>
                JsonSerializer.Serialize(new {
                    protocol_version = 1,
                    request_id = (id ?? Guid.NewGuid()).ToString("D"),
                    command
                });
            void StillNotProtected(JsonElement state)
            {
                Check(state.GetProperty("offline_prototype_only").GetBoolean());
                Check(state.GetProperty("physical_egress_block_required").GetBoolean());
                Check(!state.GetProperty("physical_egress_block_verified").GetBoolean());
                Check(!state.GetProperty("vpn_control_available").GetBoolean());
                Check(!state.GetProperty("off_committed").GetBoolean());
                Check(!state.GetProperty("service_or_ipc_connected").GetBoolean());
            }

            var store = new IntentStore(root, "intent.protected");
            var bridge = new DurableIntentBridge(store);
            var initial = Parse(bridge.Snapshot());
            StillNotProtected(initial);
            Check(initial.GetProperty("recorded_intent").GetString() == "UnknownFailClosed");
            Check(initial.GetProperty("revision").GetInt64() == 0);

            var forbidden = Parse(bridge.Process(Frame("ExplicitEnable"), false));
            Check(!forbidden.GetProperty("accepted").GetBoolean());
            Check(!File.Exists(file));
            StillNotProtected(forbidden);
            foreach (string attack in new[] {
                Frame("RequestExplicitDisable"), Frame("CommitOff"),
                Frame("InstallDriver"), "{", "null", "[]",
                "{\"protocol_version\":1,\"request_id\":\""+Guid.NewGuid().ToString("D")+"\",\"command\":\"ExplicitEnable\",\"admin\":true}"
            }) {
                var response = Parse(bridge.Process(attack, true));
                Check(!response.GetProperty("accepted").GetBoolean());
                StillNotProtected(response);
            }

            Guid fixedId = Guid.NewGuid();
            var enableFrame = Frame("ExplicitEnable", fixedId);
            var enabled = Parse(bridge.Process(enableFrame, true));
            Check(enabled.GetProperty("accepted").GetBoolean());
            Check(enabled.GetProperty("code").GetString() == "ENABLED_INTENT_DURABLY_STORED_NO_WFP");
            Check(enabled.GetProperty("recorded_intent").GetString() == "Enabled");
            Check(enabled.GetProperty("revision").GetInt64() == 1);
            StillNotProtected(enabled);
            Check(store.Read().Intent == UserIntent.Enabled);
            Check(store.Read().RequiresFailClosed);
            byte[] ciphertext = File.ReadAllBytes(file);
            Check(ciphertext.Length > 0 && ciphertext.Length < 4096);
            Check(!System.Text.Encoding.ASCII.GetString(ciphertext).Contains("Enabled"));
            var replay = Parse(bridge.Process(enableFrame, true));
            Check(!replay.GetProperty("accepted").GetBoolean());
            Check(replay.GetProperty("code").GetString() == "REPLAY_DENIED");
            Check(store.Read().Revision == 1);

            var pending = Parse(bridge.Process(Frame("RequestExplicitDisable"), true));
            Check(pending.GetProperty("accepted").GetBoolean());
            Check(pending.GetProperty("code").GetString() == "DISABLE_PENDING_NO_POLICY_RELEASE");
            Check(store.Read().Intent == UserIntent.Enabled);
            Check(store.Read().Revision == 1);
            StillNotProtected(pending);

            // Actual re-instantiation after an in-memory crash retains disk
            // Enabled (not a fabricated Off). Unknown planner needs a new
            // explicit Enable before accepting a Disable request.
            var restarted = new DurableIntentBridge(new IntentStore(root, "intent.protected"));
            var rebooted = Parse(restarted.Snapshot());
            StillNotProtected(rebooted);
            Check(rebooted.GetProperty("recorded_intent").GetString() == "Enabled");
            Check(rebooted.GetProperty("revision").GetInt64() == 1);
            Check(!Parse(restarted.Process(Frame("RequestExplicitDisable"), true))
                .GetProperty("accepted").GetBoolean());
            Check(store.Read().Revision == 1);
            var reenabled = Parse(restarted.Process(Frame("ExplicitEnable"), true));
            Check(reenabled.GetProperty("accepted").GetBoolean());
            Check(reenabled.GetProperty("revision").GetInt64() == 2);

            // External tamper changes a live bridge's expected DPAPI record.
            ciphertext = File.ReadAllBytes(file);
            ciphertext[ciphertext.Length / 2] ^= 0x10;
            File.WriteAllBytes(file, ciphertext);
            var damaged = Parse(restarted.Snapshot());
            Check(!damaged.GetProperty("accepted").GetBoolean());
            Check(damaged.GetProperty("quarantined").GetBoolean());
            Check(damaged.GetProperty("recorded_intent").GetString() == "UnknownFailClosed");
            StillNotProtected(damaged);
            Check(!Parse(restarted.Process(Frame("ExplicitEnable"), true))
                .GetProperty("accepted").GetBoolean());

            // A valid historic OFF is not a release attestation: quarantine.
            File.Delete(file);
            store.RecordExplicitChoice(UserIntent.Enabled);
            store.RecordExplicitChoice(UserIntent.Disabled);
            var historicalOff = new DurableIntentBridge(store);
            var offSnapshot = Parse(historicalOff.Snapshot());
            Check(offSnapshot.GetProperty("quarantined").GetBoolean());
            Check(offSnapshot.GetProperty("recorded_intent").GetString() == "UnknownFailClosed");
            StillNotProtected(offSnapshot);
            Check(!Parse(historicalOff.Process(Frame("ExplicitEnable"), true))
                .GetProperty("accepted").GetBoolean());

            Check(count > 90);
            Console.WriteLine("R12_DURABLE_BRIDGE_PASS: " + count +
                " checks, real Windows DPAPI+restart/tamper/replay, no Off commit," +
                " no WFP/network/SCM/production IPC");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R12_DURABLE_BRIDGE_FAIL: " +
                ex.GetType().Name + " case=" + count);
            return false;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
