using System.ServiceProcess;

namespace OracleProxy.LabManager;

// A real, independently managed Windows SCM service, completely separate
// from WireGuardTunnel$OracleProxyLab. STATUS ONLY: no tunnel control.
internal sealed class LabManagerService : ServiceBase
{
    internal const string FixedServiceName = "OracleProxyLabManager";
    private CancellationTokenSource? _stop;
    private Task? _worker;
    private Task? _adminLabWorker;
    private readonly bool _enableAdminCiLabControl;

    internal LabManagerService(bool enableAdminCiLabControl = false)
    {
        _enableAdminCiLabControl = enableAdminCiLabControl;
        ServiceName = FixedServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = false; // No Windows Event Log including any credentials
    }

    protected override void OnStart(string[] args)
    {
        _stop = new CancellationTokenSource();
        _worker = Task.Run(() => LabPipe.RunServerAsync(
            LabPipe.ProductionPipeName, false, _stop.Token));
        if (_enableAdminCiLabControl && AdminLabControl.IsDisposableCiLab())
        {
            // NOT active with the normal production service arguments.
            var control = new AdminLabControl();
            _adminLabWorker = Task.Run(() => control.ServeAsync(
                AdminLabControl.PipeName, false,
                AdminLabControl.ApplyToCiLabService, _stop.Token));
        }
    }

    protected override void OnStop()
    {
        _stop?.Cancel();
        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(5));
            _adminLabWorker?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException) { /* cancellation during shutdown */ }
        finally { _stop?.Dispose(); }
    }

    protected override void OnShutdown() => OnStop();
}
