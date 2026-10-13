using System.Text.Json;

namespace OracleProxy.Windows.Preview;

// Host-side checks only. This is NOT authentication, network IPC or WFP.
internal static class ControlProtocolSelfTests
{
    internal static bool Run()
    {
        try
        {
            int checks = 0;
            void Check(bool condition)
            {
                if (!condition)
                    throw new InvalidOperationException("Offline protocol regression at case " + checks);
                checks++;
            }

            string Frame(string command, Guid? id = null) =>
                JsonSerializer.Serialize(new {
                    protocol_version = 1,
                    request_id = (id ?? Guid.NewGuid()).ToString("D"),
                    command
                });

            var gate = new ControlProtocolSimulator();
            var on = Frame("EnableVpn");
            Check(!gate.ProcessMockRequest(on, false).Accepted);
            Check(gate.ProcessMockRequest(on, true).Accepted);
            Check(gate.ProcessMockRequest(on, true).Code == "REPLAYED_REQUEST");
            Check(gate.ProcessMockRequest(Frame("Connect"), true).Accepted);
            Check(gate.ProcessMockRequest(Frame("DisconnectTunnel"), true).Accepted);
            Check(!gate.ProcessMockRequest(Frame("DisableVpn"), false).Accepted);
            Check(gate.ProcessMockRequest(Frame("EnableVpn"), true).Snapshot.Intent
                == UserVpnIntent.Enabled);

            string[] invalidFrames = {
                "", "null", "[]", "{", "{}",
                "{}", "{\"protocol_version\":1}",
                "{\"protocol_version\":2,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"DisableVpn\"}",
                "{\"protocol_version\":1,\"request_id\":\"not-a-guid\",\"command\":\"DisableVpn\"}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000000\",\"command\":\"DisableVpn\"}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":123}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"EnableVpn\",\"endpoint\":\"bad\"}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"EnableVpn\",\"command\":\"DisableVpn\"}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"EnableVpn\",}",
                "{\"protocol_version\":true,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"EnableVpn\"}",
                "{\"protocol_version\":1,\"request_id\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"EnableVpn\",\"path\":\"C:\\\\temp\"}",
                new string('x', 2048),
            };
            foreach (string invalid in invalidFrames)
            {
                var before = gate.ProcessMockRequest(Frame("DoesNotExist"), true).Snapshot.Intent;
                var denied = gate.ProcessMockRequest(invalid, true);
                Check(!denied.Accepted);
                Check(denied.Snapshot.Intent == before);
            }

            foreach (string forbidden in new[] {
                "disabled", "disablevpn", "DISABLEVPN", "Off", "Exit",
                "ServiceStop", "SetFirewall", "RunShell", "InstallDriver",
                "SetEndpoint", "SetConfig", "DeleteTunnel", "0", "1", "2", "3"
            })
            {
                var result = gate.ProcessMockRequest(Frame(forbidden), true);
                Check(!result.Accepted && result.Code == "UNKNOWN_COMMAND");
                Check(result.Snapshot.Intent == UserVpnIntent.Enabled);
            }

            // Invalid/untrusted request cannot turn off the mock VPN protection.
            for (int i = 0; i < 30; i++)
            {
                Check(!gate.ProcessMockRequest(Frame("DisableVpn"), false).Accepted);
                Check(gate.ProcessMockRequest(Frame("NoSuchCommand"), true)
                    .Snapshot.Intent == UserVpnIntent.Enabled);
            }

            Check(gate.ProcessMockRequest(Frame("DisableVpn"), true).Accepted);
            Check(gate.ProcessMockRequest(Frame("Connect"), true).Code == "INVALID_STATE_TRANSITION");
            Check(gate.ProcessMockRequest(Frame("EnableVpn"), true).Accepted);
            Check(gate.ProcessMockRequest(Frame("Connect"), true).Accepted);

            // Replay cache is bounded in the model. On overflow deny mutation.
            // This is NOT durable replay defense and does not replace pipe ACLs.
            var capped = new ControlProtocolSimulator();
            for (int i = 0; i < 128; i++)
                Check(capped.ProcessMockRequest(Frame("EnableVpn"), true).Accepted);
            Check(capped.ProcessMockRequest(Frame("DisableVpn"), true).Code
                  == "MOCK_REPLAY_WINDOW_FULL");
            Check(capped.ProcessMockRequest(Frame("EnableVpn"), true).Snapshot.Intent
                  == UserVpnIntent.Enabled);

            return checks >= 220;
        }
        catch { return false; }
    }
}
