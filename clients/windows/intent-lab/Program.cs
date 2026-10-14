namespace OracleProxy.IntentLab;

// Has no GUI, SCM connection, driver, WFP, firewall, route or VPN operations.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1) return 3;
        return args[0] switch {
            "--offline-self-test" => IntentSelfTests.Run() ? 0 : 1,
            "--durable-bridge-self-test" => DurableBridgeSelfTests.Run() ? 0 : 1,
            _ => 3
        };
    }
}
