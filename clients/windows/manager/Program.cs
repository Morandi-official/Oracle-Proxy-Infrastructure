using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;

namespace OracleProxy.LabManager;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 3;
#if ENABLE_DISPOSABLE_LAB_CONTROLS
        if ((args.Length == 2 || args.Length == 3) &&
            args[0] == "--manager-service" &&
            args[1] == "--ci-lab-control" &&
            (args.Length == 2 || args[2] == "--ci-wfp-guard"))
        {
            if (!AdminLabControl.IsDisposableCiLab()) return 3;
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                    return 3;
                ServiceBase.Run(new LabManagerService(enableAdminCiLabControl: true,
                    enableCiWfpGuard: args.Length == 3));
                return 0;
            }
            catch { return 3; }
        }
#endif
        if (args.Length != 1) return 2;

        try
        {
            switch (args[0])
            {
                case "--manager-service":
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    {
                        if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                            return 3;
                    }
                    ServiceBase.Run(new LabManagerService());
                    return 0;

                case "--ipc-status":
                    Console.WriteLine(await LabPipe.ClientRequestAsync(
                        LabPipe.ProductionPipeName,
                        "{\"protocol_version\":1,\"command\":\"Status\"}",
                        CancellationToken.None));
                    return 0;

                case "--ipc-self-test":
                    return await LabManagerSelfTests.RunAsync() ? 0 : 1;
#if ENABLE_DISPOSABLE_LAB_CONTROLS
                case "--admin-lab-self-test":
                    return await AdminLabControlSelfTests.RunAsync() ? 0 : 1;
#endif
                case "--safe-control-gate-self-test":
                    return SafeControlGateSelfTests.Run() ? 0 : 1;

                case "--production-transition-contract-self-test":
                    return ProductionVpnCoordinatorSelfTests.Run() ? 0 : 1;

                case "--offline-intent-planner-self-test":
                    return OfflineIntentPlannerSelfTests.Run() ? 0 : 1;

                default: return 2;
            }
        }
        catch
        {
            // Never surface a raw stack trace or config/file/username to logs.
            return 3;
        }
    }
}
