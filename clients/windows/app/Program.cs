using System;
using System.Windows.Forms;

namespace OracleProxy.Windows.Preview;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // Headless smoke tests run in a hosted VM; these do not query live
        // networking, require elevation, or start the Windows Forms UI.
        if (args.Length == 1 && args[0] == "--self-test")
        {
            return PolicySelfTests.Run() ? 0 : 1;
        }
        if (args.Length == 1 && args[0] == "--protocol-self-test")
        {
            return ControlProtocolSelfTests.Run() ? 0 : 1;
        }
        if (args.Length == 1 && args[0] == "--control-self-test")
        {
            return ControlStateSelfTests.Run() ? 0 : 1;
        }
#if ORACLE_DISPOSABLE_LAB
        if (args.Length == 1 && args[0].StartsWith("--ci-lab-", StringComparison.Ordinal))
        {
            string? operation = args[0] switch {
                "--ci-lab-start-a" => "StartLabPeerA",
                "--ci-lab-stop-a" => "StopLabPeerA",
                "--ci-lab-start-b" => "StartLabPeerB",
                "--ci-lab-stop-b" => "StopLabPeerB",
                _ => null
            };
            if (operation is null || !LabAdminControlClient.OnDisposableRunner()) return 3;
            try {
                return LabAdminControlClient.SendAsync(operation, CancellationToken.None)
                    .GetAwaiter().GetResult() ? 0 : 3;
            }
            catch { return 3; }
        }
#endif
        if (args.Length == 1 && args[0] == "--manager-spoof-test")
        {
            return ManagerStatusSelfTests.RejectRoguePipeAsync()
                .GetAwaiter().GetResult() ? 0 : 1;
        }
        if (args.Length == 1 && args[0] == "--manager-status-self-test")
        {
            try
            {
                var result = ManagerStatusClient.ReadAsync(CancellationToken.None)
                    .GetAwaiter().GetResult();
                return result.StatusPipeAuthenticated && !result.MutationsAvailable &&
                       result.Connected == "unverified" &&
                       result.LeakProtection == "unverified" ? 0 : 1;
            }
            catch { return 1; }
        }
        if (args.Length == 1 && args[0] == "--diagnostics-self-test")
        {
            try
            {
                var report = SanitizedDiagnostics.CollectAsync(
                    CancellationToken.None).GetAwaiter().GetResult();
                return report.PhysicalAdapterCount >= 0 &&
                       !string.IsNullOrWhiteSpace(report.CollectedAtUtc) ? 0 : 1;
            }
            catch { return 1; }
        }
        if (args.Length > 0)
        {
            return 2;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}
