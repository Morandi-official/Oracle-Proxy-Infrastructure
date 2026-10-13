namespace OracleProxy.IntentLab;

// Has no GUI, SCM connection, driver, WFP, firewall, route or VPN operations.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1 ||
            args[0] != "--offline-self-test")
            return 3;
        return IntentSelfTests.Run() ? 0 : 1;
    }
}
