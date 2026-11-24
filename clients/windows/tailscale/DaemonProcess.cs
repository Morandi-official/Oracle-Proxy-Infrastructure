using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Tailscale;

/// <summary>Owns the dedicated Tailscale daemon started from an installed, verified bundle.</summary>
internal sealed class DaemonProcess : IAsyncDisposable
{
    private readonly Process _process;
    private readonly SafeFileHandle _job;
    internal LocalControl Control { get; }
    internal string AdapterName { get; }

    private DaemonProcess(Process process, SafeFileHandle job, LocalControl control, string adapterName)
    {
        _process = process;
        _job = job;
        Control = control;
        AdapterName = adapterName;
    }

    internal static async Task<DaemonProcess> Start(
        string trustedExecutable, string privateStateDirectory, CancellationToken cancellation)
    {
        var instance = Guid.NewGuid().ToString("N");
        var adapter = "ProxyTail-" + instance[..12];
        var control = new LocalControl(instance);
        var start = new ProcessStartInfo(Path.GetFullPath(trustedExecutable))
        {
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
        };
        foreach (string name in start.Environment.Keys.ToArray())
        {
            if (name.StartsWith("TS_", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("TAILSCALE_", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("ORACLE_CLIENT_ACCEPTANCE_", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith("_PROXY", StringComparison.OrdinalIgnoreCase))
                start.Environment.Remove(name);
        }
        start.Environment["TS_NO_LOGS_NO_SUPPORT"] = "true";
        start.ArgumentList.Add(@"--socket=\\.\pipe\" + LocalControl.PipePrefix + instance);
        start.ArgumentList.Add("--state=" + Path.Combine(Path.GetFullPath(privateStateDirectory), "state"));
        start.ArgumentList.Add("--tun=" + adapter);
        start.ArgumentList.Add("--port=0");

        Process? process = null;
        SafeFileHandle? job = null;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            (process, job) = DaemonConsole.Start(start);
            using var readiness = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            readiness.CancelAfter(TimeSpan.FromSeconds(12));
            while (true)
            {
                if (process.HasExited)
                    throw new IOException("TAILSCALE_DAEMON_EXITED");
                try
                {
                    await control.ReadState(readiness.Token);
                    break;
                }
                catch (HttpRequestException) when (!readiness.IsCancellationRequested) { }
                catch (OperationCanceledException) when (!readiness.IsCancellationRequested) { }
                await Task.Delay(125, readiness.Token);
            }
            return new DaemonProcess(process, job, control, adapter);
        }
        catch
        {
            control.Dispose();
            if (process is not null)
            {
                try { await EndProcess(process); }
                finally
                {
                    job?.Dispose();
                    process.Dispose();
                }
            }
            throw;
        }
    }

    private static async Task EndProcess(Process process)
    {
        if (DaemonConsole.SignalExit(process))
        {
            try
            {
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                return;
            }
            catch (TimeoutException) { }
        }
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) when (process.HasExited) { }
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!_process.HasExited)
                await Control.Stop();
        }
        finally
        {
            Control.Dispose();
            try { await EndProcess(_process); }
            finally
            {
                _job.Dispose();
                _process.Dispose();
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            try
            {
                while (NetworkInterface.GetAllNetworkInterfaces().Any(value => value.Name == AdapterName))
                    await Task.Delay(125, timeout.Token);
            }
            catch (OperationCanceledException)
            {
                throw new IOException("TAILSCALE_ADAPTER_STILL_PRESENT");
            }
        }
    }
}
