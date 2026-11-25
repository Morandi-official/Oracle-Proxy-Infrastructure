using System.Diagnostics;
using System.Net;
using System.Text.Json;
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
        string trustedExecutable, string privateStateDirectory, CancellationToken cancellation,
        Action<string>? timing = null, Task? authorization = null,
        string coordinatorTlsHost = "vpn-admin.morandi.dpdns.org")
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
        // The Oracle coordinator exposes Noise upgrades only on HTTPS.
        start.Environment["TS_FORCE_NOISE_443"] = "true";
        start.Environment["TS_ORACLE_PROXY_TLS_HOST"] = coordinatorTlsHost;
        start.ArgumentList.Add(@"--socket=\\.\pipe\" + LocalControl.PipePrefix + instance);
        start.ArgumentList.Add("--state=" + Path.Combine(Path.GetFullPath(privateStateDirectory), "state"));
        start.ArgumentList.Add("--statedir=" + Path.GetFullPath(privateStateDirectory));
        start.ArgumentList.Add("--tun=" + adapter);
        // Keep the upstream Windows preferred port across reconnects.
        // Magicsock still chooses an available port if this one is occupied.
        start.ArgumentList.Add("--port=41641");

        Process? process = null;
        SafeFileHandle? job = null;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            (process, job) = DaemonConsole.Start(start);
            timing?.Invoke("daemon_spawned");
            using var observation = timing is null ? null : CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            var adapterObservation = observation is null ? Task.CompletedTask : ObserveAdapter(adapter, timing!, observation.Token);
            try
            {
                // Opening LocalAPI selects the Windows user and can resume its
                // persisted profile. Allow process and interface initialization
                // in parallel, but hold off selecting any profile until the
                // account service authorizes this connection.
                if (authorization is not null)
                    await authorization.WaitAsync(cancellation);
                using var readiness = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                readiness.CancelAfter(TimeSpan.FromSeconds(12));
                while (true)
                {
                    if (process.HasExited)
                        throw new IOException("TAILSCALE_DAEMON_EXITED");
                    try
                    {
                        // The watcher itself proves LocalAPI readiness and selects the
                        // Windows profile, so a separate status request adds no check.
                        await control.KeepWindowsProfileSelected(readiness.Token);
                        break;
                    }
                    catch (HttpRequestException) when (!readiness.IsCancellationRequested) { }
                    catch (OperationCanceledException) when (!readiness.IsCancellationRequested) { }
                    await Task.Delay(50, readiness.Token);
                }
            }
            catch (OperationCanceledException error) when (!cancellation.IsCancellationRequested)
            {
                throw new IOException("TAILSCALE_ENGINE_START_TIMEOUT", error);
            }
            finally
            {
                observation?.Cancel();
                await adapterObservation;
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

    internal static async Task CacheVerifiedCoordinatorAddress(
        string state, Uri coordinator, IPAddress address, CancellationToken cancellation)
    {
        string host = coordinator.IdnHost.ToLowerInvariant();
        if (host.Length == 0 || host.Split('.').Any(label => label.Length == 0 ||
            label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new IOException("INVALID_TAILSCALE_COORDINATOR");

        // Match the private DNS cache format of the pinned Tailscale build.
        // The caller supplies an address already authenticated by the account exchange.
        string directory = Path.Combine(state, "dns-cache");
        var entry = Directory.CreateDirectory(directory);
        if ((entry.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (entry.Parent!.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("TAILSCALE_DNS_CACHE_PATH_INVALID");

        string path = Path.Combine(directory, "dns-" + host + ".json");
        string temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            byte[] contents = JsonSerializer.SerializeToUtf8Bytes(new { Resolver = "fallback", A = new[] { address.ToString() } });
            await File.WriteAllBytesAsync(temporary, contents, cancellation);
            File.Move(temporary, path, overwrite: true);
        }
        finally { File.Delete(temporary); }
    }

    private static async Task ObserveAdapter(string adapter, Action<string> timing, CancellationToken cancellation)
    {
        try
        {
            while (!NetworkInterface.GetAllNetworkInterfaces().Any(value => value.Name == adapter))
                await Task.Delay(30, cancellation).ConfigureAwait(false);
            timing("adapter_visible");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (NetworkInformationException) { }
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
