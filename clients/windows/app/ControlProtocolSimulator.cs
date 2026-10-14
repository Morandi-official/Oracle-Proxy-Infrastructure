using System.Text;
using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// Strict, OFFLINE test-only protocol validator. Does not open a pipe/socket,
// authenticate Windows callers or execute privileged commands.
internal sealed record MockControlReply(
    bool Accepted, string Code, ControlStateSnapshot Snapshot);

internal sealed class ControlProtocolSimulator
{
    private const int MaxRequestBytes = 1024;
    private const int MaxAcceptedRequests = 128;
    private readonly HashSet<Guid> _seen = new();
    private readonly ControlStateSimulator _controller;

    internal ControlProtocolSimulator(ControlStateSimulator? controller = null)
    {
        _controller = controller ?? new ControlStateSimulator();
    }

    internal MockControlReply ProcessMockRequest(string? payload, bool mockCallerAuthorized)
    {
        if (!mockCallerAuthorized)
            return Deny("UNAUTHORIZED_MOCK_CALLER");

        if (payload is null || Encoding.UTF8.GetByteCount(payload) > MaxRequestBytes ||
            payload.Length == 0)
            return Deny("INVALID_FRAME_SIZE");

        Guid requestId;
        SimulatedUserCommand command;
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Deny("INVALID_ENVELOPE");

            // Unknown keys and duplicates are rejected. No transport address,
            // private key, process path or arbitrary shell command is accepted.
            var found = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (property.Name is not ("protocol_version" or "request_id" or "command") ||
                    !found.Add(property.Name))
                    return Deny("UNKNOWN_OR_DUPLICATE_FIELD");
            }
            if (found.Count != 3 ||
                !root.TryGetProperty("protocol_version", out JsonElement version) ||
                version.ValueKind != JsonValueKind.Number ||
                !version.TryGetInt32(out int versionNumber) || versionNumber != 1 ||
                !root.TryGetProperty("request_id", out JsonElement id) ||
                id.ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(id.GetString(), "D", out requestId) ||
                requestId == Guid.Empty ||
                !root.TryGetProperty("command", out JsonElement requested) ||
                requested.ValueKind != JsonValueKind.String)
                return Deny("INVALID_ENVELOPE");

            // Exact, case-sensitive command strings only. Enum integers are forbidden.
            string? name = requested.GetString();
            switch (name)
            {
                case "EnableVpn": command = SimulatedUserCommand.EnableVpn; break;
                case "DisableVpn": command = SimulatedUserCommand.DisableVpn; break;
                case "Connect": command = SimulatedUserCommand.Connect; break;
                case "DisconnectTunnel": command = SimulatedUserCommand.DisconnectTunnel; break;
                default: return Deny("UNKNOWN_COMMAND");
            }
        }
        catch (JsonException)
        {
            return Deny("INVALID_JSON");
        }

        if (_seen.Contains(requestId))
            return Deny("REPLAYED_REQUEST");
        if (_seen.Count >= MaxAcceptedRequests)
            return Deny("MOCK_REPLAY_WINDOW_FULL");

        if (!_controller.ApplyMockAuthorizedUserCommand(command, mockCallerAuthorized: true))
            return Deny("INVALID_STATE_TRANSITION");

        _seen.Add(requestId);
        return new MockControlReply(true, "MOCK_COMMAND_ACCEPTED", _controller.Snapshot());
    }

    private MockControlReply Deny(string code) =>
        new(false, code, _controller.Snapshot());
}
