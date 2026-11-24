namespace OracleProxy.Tailscale;

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        if (arguments.Length == 2 && arguments[0] == "--acceptance" &&
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") == "github-hosted")
            return LiveAcceptance.Run(arguments[1]).GetAwaiter().GetResult();
        if (arguments.Length != 0) return 2;

        ApplicationConfiguration.Initialize();
        using var owner = new Mutex(true, @"Local\Morandi.Proxy.Tailscale", out bool acquired);
        if (!acquired) return 0;
        using var form = new MainForm();
        Application.Run(form);
        return 0;
    }
}
