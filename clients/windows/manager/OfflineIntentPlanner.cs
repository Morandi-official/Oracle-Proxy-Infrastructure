using System.Text;
using System.Text.Json;

namespace OracleProxy.LabManager;

// R4 is a PURE IN-MEMORY EXPERIMENT. NOT wired to a GUI, production pipe,
// privileged SCM dispatcher, DPAPI store, native tunnel or Windows WFP.
// A Boolean below is injected only in offline tests; never accept a
// client-provided "authorized" field in a future production service.
internal enum OfflineIntent { UnknownFailClosed, Enabled, Disabled }

internal sealed class OfflineIntentPlanner
{
    private const int FrameMaxBytes = 512;
    private const int MaxSeen = 128;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly HashSet<Guid> _seen = new();
    private OfflineIntent _intent = OfflineIntent.UnknownFailClosed;
    private bool _disablePending;
    private long _revision;

    private string Response(bool accepted, string code) => JsonSerializer.Serialize(new {
        schema_version = 1,
        accepted,
        code,
        offline_model_only = true,
        state = _intent.ToString(),
        revision = _revision,
        disable_pending = _disablePending,
        physical_egress_block_required = _intent != OfflineIntent.Disabled,
        actual_wfp_enforcement = false,
        production_ipc_commands_enabled = false,
        durable_store_connected = false
    });

    // Disconnects, service crashes and stale handshakes are observations.
    // They must NEVER alter explicit user intent, including while Off is
    // pending a not-yet-implemented verified OS policy release.
    internal string ObserveDisconnect() => Response(true, "DISCONNECT_KEEPS_INTENT");
    internal string ObserveServiceCrash() => Response(true, "SERVICE_CRASH_KEEPS_INTENT");
    internal string ObserveStaleHandshake() => Response(true, "HANDSHAKE_STALE_KEEPS_INTENT");
    internal string Snapshot() => Response(true, "OFFLINE_STATUS");

    // This parser is NEVER called by LabPipe or AdminLabControl. The bool
    // must eventually be derived from genuine Windows caller impersonation,
    // token policy and explicit user action, never from request JSON.
    internal string ProcessOfflineRequest(string? payload, bool verifiedOsAdministrator)
    {
        if (!verifiedOsAdministrator) return Response(false, "OS_TOKEN_NOT_AUTHORIZED");
        if (string.IsNullOrEmpty(payload) || Utf8.GetByteCount(payload) > FrameMaxBytes)
            return Response(false, "INVALID_FRAME");

        Guid requestId;
        string? command;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(payload, new JsonDocumentOptions {
                MaxDepth = 3,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Response(false, "INVALID_FRAME");
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (property.Name is not ("protocol_version" or "request_id" or "command") ||
                    !fields.Add(property.Name))
                    return Response(false, "EXTRA_OR_DUPLICATE_FIELD");
            }
            if (fields.Count != 3 ||
                root.GetProperty("protocol_version").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("protocol_version").TryGetInt32(out int version) ||
                version != 1 ||
                root.GetProperty("request_id").ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(root.GetProperty("request_id").GetString(), "D", out requestId) ||
                requestId == Guid.Empty ||
                root.GetProperty("command").ValueKind != JsonValueKind.String)
                return Response(false, "INVALID_FRAME");
            command = root.GetProperty("command").GetString();
        }
        catch (JsonException) { return Response(false, "INVALID_JSON"); }

        if (command is not ("ExplicitEnable" or "RequestExplicitDisable"))
            return Response(false, "MUTATION_UNSUPPORTED");
        if (_seen.Contains(requestId)) return Response(false, "REPLAY_DENIED");
        // Refuse capacity exhaustion BEFORE reservation. This is a bounded
        // negative cache with no eviction that would admit old request IDs.
        if (_seen.Count >= MaxSeen)
            return Response(false, "REPLAY_CACHE_EXHAUSTED");
        _seen.Add(requestId);

        if (command == "ExplicitEnable")
        {
            // An Enabled INTENT is not proof of actual packet protection.
            // The real service must install/verify persistent WFP policy
            // BEFORE ever allowing production connect requests.
            _intent = OfflineIntent.Enabled;
            _disablePending = false;
            _revision++;
            return Response(true, "ENABLED_INTENT_MODEL_ONLY");
        }

        if (_intent != OfflineIntent.Enabled)
            return Response(false, "UNKNOWN_CANNOT_DISABLE");
        _disablePending = true;
        // There is deliberately NO CommitOff, WFP release or physical
        // egress operation. Requested Off stays fail-closed in this model.
        return Response(true, "DISABLE_REQUESTED_BUT_NOT_COMMITTED");
    }
}
