using System.Diagnostics;
using System.Text.Json;

namespace OracleProxy.Windows.Preview;

internal sealed record DiagnosticSnapshot(
    int PhysicalAdapterCount, bool IPv4DefaultRoute, bool IPv6DefaultRoute,
    string WireSockDriverState, string WireSockServiceState,
    string WireGuardManagerState, bool UuServerPresent, string CollectedAtUtc);

internal static class SanitizedDiagnostics
{
    public static async Task<DiagnosticSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        string script = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "diagnostics", "Collect-ReadOnly.ps1"));
        if (!File.Exists(script))
            throw new InvalidOperationException("缺少诊断组件。请重新解压完整的软件包。");

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string ps = Path.Combine(windows, "System32", "WindowsPowerShell",
            "v1.0", "powershell.exe");
        if (!File.Exists(ps))
            throw new InvalidOperationException("未找到 Windows PowerShell。");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = ps,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = AppContext.BaseDirectory
            }
        };
        foreach (string argument in new[] {
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", script
        })
            process.StartInfo.ArgumentList.Add(argument);

        bool started = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(25));
        try
        {
            if (!process.Start())
                throw new InvalidOperationException("诊断组件无法启动。");
            started = true;
            Task<string> stdOut = process.StandardOutput.ReadToEndAsync();
            Task<string> stdErr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(timeout.Token);
            string output = await stdOut;
            _ = await stdErr; // Never display raw OS messages or executable paths.

            if (process.ExitCode != 0)
                throw new InvalidOperationException("诊断失败；未修改任何网络配置。");

            using JsonDocument document = JsonDocument.Parse(output);
            JsonElement root = document.RootElement;
            if (root.GetProperty("schema_version").GetInt32() != 1 ||
                root.GetProperty("mode").GetString() != "read_only_local" ||
                root.GetProperty("vpn_connected").GetString() != "unknown")
                throw new InvalidOperationException("诊断数据版本不兼容。");

            JsonElement network = root.GetProperty("physical_network");
            JsonElement services = root.GetProperty("services");
            JsonElement drivers = root.GetProperty("drivers");
            JsonElement uu = root.GetProperty("uu_processes_present");

            return new DiagnosticSnapshot(
                network.GetProperty("active_physical_adapter_count").GetInt32(),
                network.GetProperty("ipv4_default_route_present").GetBoolean(),
                network.GetProperty("ipv6_default_route_present").GetBoolean(),
                drivers.GetProperty("WireSock").GetString() ?? "Unknown",
                services.GetProperty("WireSockConnectService").GetString() ?? "Unknown",
                services.GetProperty("WireGuardManager").GetString() ?? "Unknown",
                uu.GetProperty("GameViewerServer.exe").GetBoolean(),
                root.GetProperty("collected_at_utc").GetString() ?? "Unknown");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException("诊断超时；未修改任何网络配置。");
        }
        finally
        {
            if (started && !process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }
            }
        }
    }
}
