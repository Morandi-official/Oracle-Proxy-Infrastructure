using System.Security.Principal;
using System.Text.Json;

namespace OracleProxy.LabManager;

internal static class LabManagerSelfTests
{
    internal static async Task<bool> RunAsync()
    {
        int checks = 0;
        static string Claim(string command) =>
            "{\"protocol_version\":1,\"command\":\"" + command + "\"}";
        void Assert(bool value)
        {
            if (!value) throw new InvalidOperationException("lab IPC invariant " + checks);
            checks++;
        }

        try
        {
            // Pure parser defense must fail shut even for privileged test callers.
            Assert(JsonDocument.Parse(LabPipe.EvaluateFrame(Claim("Status"), true))
                .RootElement.GetProperty("ok").GetBoolean());
            foreach (string command in new[] {
                "DisableVpn", "EnableVpn", "Connect", "DisconnectTunnel",
                "StartService", "InstallDriver", "RunShell", "SetConfig"
            })
            {
                var doc = JsonDocument.Parse(
                    LabPipe.EvaluateFrame(Claim(command), true));
                Assert(!doc.RootElement.GetProperty("ok").GetBoolean());
                Assert(doc.RootElement.GetProperty("code").GetString()
                       == "MUTATION_DISABLED");
            }

            Assert(LabPipe.EvaluateFrame(Claim("Status"), false)
                .Contains("ACCESS_DENIED", StringComparison.Ordinal));
            foreach (string invalid in new[] {
                "", "null", "[]", "{}", "{", new string('x', 2048),
                "{\"protocol_version\":0,\"command\":\"Status\"}",
                "{\"protocol_version\":1,\"command\":\"Status\",\"caller_sid\":\"S-1-5-18\"}",
                "{\"protocol_version\":1,\"command\":\"Status\",\"command\":\"DisableVpn\"}",
                "{\"protocol_version\":1,\"command\":123}",
                "{\"protocol_version\":1,\"command\":\"Status\",}"
            })
            {
                Assert(!JsonDocument.Parse(LabPipe.EvaluateFrame(invalid, true))
                    .RootElement.GetProperty("ok").GetBoolean());
            }

            string testName = "OracleProxyLabSmoke." + Guid.NewGuid().ToString("N");
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            Task host = Task.Run(() =>
                LabPipe.RunServerAsync(testName, true, stop.Token, 4));
            string[] requests = {
                Claim("Status"), Claim("DisableVpn"),
                "{\"protocol_version\":1,\"command\":\"Status\",\"caller_sid\":\"S-1-5-18\"}",
                new string('x', 513)
            };
            for (int i = 0; i < requests.Length; i++)
            {
                string response = await LabPipe.ClientRequestAsync(
                    testName, requests[i], stop.Token);
                using var doc = JsonDocument.Parse(response);
                Assert(doc.RootElement.GetProperty("ok").GetBoolean() == (i == 0));
                Assert(doc.RootElement.GetProperty("native_dll_loaded").GetBoolean() == false);
                Assert(doc.RootElement.GetProperty("leak_protection").GetString() == "unverified");
            }
            await host.WaitAsync(TimeSpan.FromSeconds(5));
            Assert(checks >= 25);
            Console.WriteLine("PASS: Windows pipe OS identity and read-only control; no service/driver installed");
            return true;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("FAIL: lab manager selftest " + e.GetType().Name +
                                    " (assertions=" + checks + ")");
            return false;
        }
    }
}
