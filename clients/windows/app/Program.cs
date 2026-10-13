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
        if (args.Length > 0)
        {
            return 2;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}
