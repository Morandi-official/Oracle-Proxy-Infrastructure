using System.IO.Pipes;

namespace OracleProxy.Windows.Preview;

// A real Windows pipe owned by this unprivileged test process must never
// impersonate the installed LocalSystem SCM manager's STATUS response.
// Disposable hosted Windows runner only: no services or networking touched.
internal static class ManagerStatusSelfTests
{
    internal static async Task<bool> RejectRoguePipeAsync()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var deadline = new CancellationTokenSource(
                TimeSpan.FromSeconds(10));
            using var fake = new NamedPipeServerStream(
                ManagerStatusClient.PipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            Task connected = fake.WaitForConnectionAsync(deadline.Token);

            try
            {
                await ManagerStatusClient.ReadAsync(deadline.Token);
                Console.Error.WriteLine("FAIL: rogue pipe was trusted");
                return false;
            }
            catch (InvalidOperationException ex) when (
                ex.Message == ManagerStatusClient.UntrustedEndpointMessage)
            {
                await connected.WaitAsync(TimeSpan.FromSeconds(3));
                if (!fake.IsConnected) return false;
                Console.WriteLine(
                    "PASS: real named pipe from wrong process rejected before status request");
                return true;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL: rogue endpoint test " +
                                    ex.GetType().Name);
            return false;
        }
    }
}
