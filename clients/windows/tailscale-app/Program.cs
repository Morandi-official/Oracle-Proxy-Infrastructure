namespace OracleProxy.Tailscale;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var owner = new Mutex(true, @"Local\Morandi.Proxy.Tailscale", out bool acquired);
        if (!acquired) return;
        using var form = new MainForm();
        Application.Run(form);
    }
}
