using System.Windows.Forms;

namespace OracleProxy.AppSocks5.GUI.Experimental;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args is ["--offline-self-test"])
            return SshInput.SelfTest() ? 0 : 1;
        if (args is ["--job-self-test"])
            return ChildProcessLease.JobSelfTest() ? 0 : 1;
        if (args is ["--form-self-test"])
        {
            ApplicationConfiguration.Initialize();
            using var testForm = new MainForm();
            return testForm.Text.Contains("R56", StringComparison.Ordinal) &&
                testForm.Controls.Count > 0 ? 0 : 1;
        }
        if (args.Length != 0)
            return 2;

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}
