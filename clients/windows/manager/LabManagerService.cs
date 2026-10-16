using System.ServiceProcess;

namespace OracleProxy.LabManager;

// A real, independently managed Windows SCM service, completely separate
// from WireGuardTunnel$OracleProxyLab. STATUS ONLY: no tunnel control.
internal sealed class LabManagerService : ServiceBase
{
    internal const string FixedServiceName = "OracleProxyLabManager";
    private CancellationTokenSource? _stop;
    private Task? _worker;
    private Task? _safeControlWorker;
#if ENABLE_DISPOSABLE_LAB_CONTROLS
    private Task? _adminLabWorker;
    private readonly bool _enableAdminCiLabControl;
    private readonly bool _enableCiWfpGuard;
    private Task? _ciWfpWatch;
    private int _ciWfpCompromised;

    internal LabManagerService(bool enableAdminCiLabControl = false,
                               bool enableCiWfpGuard = false)
    {
        _enableAdminCiLabControl = enableAdminCiLabControl;
        _enableCiWfpGuard = enableCiWfpGuard;
#else
    internal LabManagerService()
    {
#endif
        ServiceName = FixedServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = false; // No Windows Event Log including any credentials
    }

    protected override void OnStart(string[] args)
    {
        // Read the native BFE state from the actual LocalSystem SCM process.
        // Neither presence of BFE nor any reserved provider can enable a
        // connection or authorize filter removal. This is an inspection only.
        NativeWfpReadOnlySnapshot snapshot = NativeWfpReadOnlyAudit.Read();
        if (!snapshot.LocalSystemSessionZero || snapshot.MayStartTunnel ||
            snapshot.MayReleaseFilter || snapshot.FullDeviceFailClosedVerified)
            throw new InvalidOperationException("R35 SCM identity/audit gate closed");
#if ENABLE_DISPOSABLE_LAB_CONTROLS
        // The OS-backed, persistent WFP filter is installed by this actual
        // LocalSystem SCM process BEFORE any pipe begins accepting requests.
        // Never available in the normal manager binary or service arguments.
        if (_enableCiWfpGuard)
        {
            try { CiOnlyWfpGuard.Install(); }
            catch (Exception ex)
            {
                // Numeric CI-only startup failure classes, no sensitive
                // configuration paths or native COM messages in logs.
                ExitCode = ex is System.Runtime.InteropServices.COMException ? 91 :
                    ex is InvalidOperationException ? 92 : 93;
                throw;
            }
        }
#endif
        _stop = new CancellationTokenSource();
        _worker = Task.Run(() => LabPipe.RunServerAsync(
            LabPipe.ProductionPipeName, false, _stop.Token));
        // Admin-only, fixed-profile control requests always deny OS mutations
        // until independent, real WFP enforcement is available.
        _safeControlWorker = Task.Run(() =>
            new SafeControlGate().ServeAsync(_stop.Token));
#if ENABLE_DISPOSABLE_LAB_CONTROLS
        if (_enableAdminCiLabControl && AdminLabControl.IsDisposableCiLab())
        {
            // NOT active with the normal production service arguments.
            var control = new AdminLabControl();
            _adminLabWorker = Task.Run(() => control.ServeAsync(
                AdminLabControl.PipeName, false,
                action =>
                {
                    if (_enableCiWfpGuard &&
                        (action is LabControlAction.StartA or LabControlAction.StartB) &&
                        (Volatile.Read(ref _ciWfpCompromised) != 0 ||
                         !CiOnlyWfpGuard.IsActive()))
                        return false;
                    return AdminLabControl.ApplyToCiLabService(action);
                }, _stop.Token));
            if (_enableCiWfpGuard)
                _ciWfpWatch = Task.Run(() => WatchCiWfpAsync(_stop.Token));
        }
#endif
    }

#if ENABLE_DISPOSABLE_LAB_CONTROLS
    // Lab-only tamper response. The actual OS firewall rule persists through
    // manager death; if an administrator deletes it while we are alive,
    // latch a permanent start refusal and stop only fixed CI tunnel peers.
    // 750ms polling is not packet-atomic and is NOT production fail-close.
    private async Task WatchCiWfpAsync(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                if (!CiOnlyWfpGuard.IsActive())
                {
                    Interlocked.Exchange(ref _ciWfpCompromised, 1);
                    AdminLabControl.ApplyToCiLabService(LabControlAction.StopA);
                    AdminLabControl.ApplyToCiLabService(LabControlAction.StopB);
                    return;
                }
                await Task.Delay(750, token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch
        {
            Interlocked.Exchange(ref _ciWfpCompromised, 1);
            // Even on transient verifier errors, do not permit new starts.
            AdminLabControl.ApplyToCiLabService(LabControlAction.StopA);
            AdminLabControl.ApplyToCiLabService(LabControlAction.StopB);
        }
    }
#endif

    protected override void OnStop()
    {
        _stop?.Cancel();
        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(5));
            _safeControlWorker?.Wait(TimeSpan.FromSeconds(5));
#if ENABLE_DISPOSABLE_LAB_CONTROLS
            _adminLabWorker?.Wait(TimeSpan.FromSeconds(5));
            _ciWfpWatch?.Wait(TimeSpan.FromSeconds(5));
#endif
        }
        catch (AggregateException) { /* cancellation during shutdown */ }
        finally { _stop?.Dispose(); }
    }

    protected override void OnShutdown() => OnStop();
}
