using System.Text.Json;
using OracleProxy.LabManager;

namespace OracleProxy.IntentLab;

// R12: OFFLINE composition of R4's strict request parser and R1's REAL
// Windows machine-DPAPI file store. NOT served over IPC or wired to WFP.
// The injected authorization Boolean is only valid in these isolated tests;
// a future Windows service MUST derive it using caller token impersonation.
internal sealed class DurableIntentBridge
{
    private readonly IntentStore _store;
    private readonly OfflineIntentPlanner _planner = new();
    private UserIntent _expectedIntent;
    private long _expectedRevision;
    private bool _quarantined;

    internal DurableIntentBridge(IntentStore store)
    {
        _store = store;
        IntentSnapshot previous = store.Read();
        _expectedRevision = previous.Revision;
        _expectedIntent = previous.Intent;
        // A recovered OFF file cannot be proof of policy release. An
        // unreadable (but existing) DPAPI file is also untrusted.
        _quarantined = previous.Intent == UserIntent.Disabled ||
            (previous.Intent == UserIntent.UnknownFailClosed &&
             previous.Reason != "MISSING_FILE");
    }

    private bool MatchesStore()
    {
        IntentSnapshot now = _store.Read();
        bool matches = now.Revision == _expectedRevision &&
            now.Intent == _expectedIntent &&
            (now.Intent != UserIntent.UnknownFailClosed ||
             now.Reason == "MISSING_FILE");
        if (!matches) _quarantined = true;
        return matches && !_quarantined;
    }

    private string Reply(bool accepted, string code)
    {
        IntentSnapshot now = _store.Read();
        return JsonSerializer.Serialize(new {
            schema_version = 1, accepted, code,
            offline_prototype_only = true,
            durable_store_kind = "windows_machine_dpapi",
            recorded_intent = _quarantined ? "UnknownFailClosed" : now.Intent.ToString(),
            revision = _quarantined ? 0 : now.Revision,
            quarantined = _quarantined,
            // A saved On is only DESIRED state. It does not block packets.
            physical_egress_block_required = true,
            physical_egress_block_verified = false,
            off_committed = false,
            vpn_control_available = false,
            service_or_ipc_connected = false
        });
    }

    internal string Snapshot()
    {
        if (!MatchesStore()) return Reply(false, "STATE_QUARANTINED");
        return Reply(true, "OFFLINE_DURABLE_SNAPSHOT");
    }

    internal string Process(string? payload, bool verifiedOsAdministrator)
    {
        if (!verifiedOsAdministrator) return Reply(false, "OS_AUTHORIZATION_REQUIRED");
        if (!MatchesStore()) return Reply(false, "STATE_QUARANTINED");
        string planned = _planner.ProcessOfflineRequest(payload, true);
        using var json = JsonDocument.Parse(planned);
        JsonElement root = json.RootElement;
        bool accepted = root.GetProperty("accepted").GetBoolean();
        string code = root.GetProperty("code").GetString() ?? "INVALID";
        if (!accepted) return Reply(false, code);

        if (code == "DISABLE_REQUESTED_BUT_NOT_COMMITTED")
        {
            // Do not call RecordExplicitChoice(Disabled). A real OFF must
            // follow VERIFIED WFP removal that does not strand UU/WireSock.
            return Reply(true, "DISABLE_PENDING_NO_POLICY_RELEASE");
        }
        if (code != "ENABLED_INTENT_MODEL_ONLY")
            return Reply(false, "UNSUPPORTED_TRANSITION");

        try
        {
            IntentSnapshot after = _store.RecordExplicitChoice(UserIntent.Enabled);
            if (after.Intent != UserIntent.Enabled ||
                after.Revision != checked(_expectedRevision + 1))
            {
                _quarantined = true;
                return Reply(false, "DURABLE_WRITE_UNVERIFIED");
            }
            _expectedIntent = after.Intent;
            _expectedRevision = after.Revision;
            return Reply(true, "ENABLED_INTENT_DURABLY_STORED_NO_WFP");
        }
        catch (Exception ex) when (ex is InvalidOperationException or
            UnauthorizedAccessException or IOException or OverflowException or
            ArgumentException)
        {
            // R4 memory state may now be Ahead of disk: never assert healthy.
            _quarantined = true;
            return Reply(false, "DURABLE_WRITE_FAILED_FAIL_CLOSED");
        }
    }
}
