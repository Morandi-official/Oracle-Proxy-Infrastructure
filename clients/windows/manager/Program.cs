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
        if (args.Length == 2 && args[0] == "--manager-service" &&
            args[1] == "--ci-lab-control")
        {
            if (!AdminLabControl.IsDisposableCiLab()) return 3;
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                if (!identity.IsSystem || Process.GetCurrentProcess().SessionId != 0)
                    return 3;
                ServiceBase.Run(new LabManagerService(enableAdminCiLabControl: true));
                return 0;
            }
            catch { return 3; }
        }
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
                case "--admin-lab-self-test":
                    return await AdminLabControlSelfTests.RunAsync() ? 0 : 1;

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
