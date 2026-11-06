using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal sealed partial class VpnRuntime
{
    private volatile UdpDiagnosticRunner? _udpDiagnostics;
    private bool Diagnosing=>_udpDiagnostics?.Running==true;
    private async Task BeginUdpDiagnostics()
    {
        if(Diagnosing)throw new IOException("DIAGNOSTIC_BUSY");
        if(_state?["udp_diagnostics_available"]?.GetValue<bool>()!=true)throw new IOException("UDP_DIAGNOSTIC_NOT_AVAILABLE");
        if(!SessionAuthorized || !DeviceRegistration.Confirmed(_state))throw new IOException("LOGIN_REQUIRED");
        if(_secret.ConnectIntent || _secret.RecoveryRequired || NativeGuard.Active || _mode!="disconnected")
            throw new IOException("DISCONNECT_BEFORE_UDP_DIAGNOSTIC");
        _prepareUntil=default;_prepareMayStartCore=false;_prepareRetryAfter=default;
        await StopCore();await EnsureTunnelRemoved();
        _udpDiagnostics?.Dispose();
        var runner=new UdpDiagnosticRunner();_udpDiagnostics=runner;
        _stage="UDP_DIAGNOSTIC";_error="";_failure=null;
        runner.Start(_state!,_secret);
    }
    private async Task EndUdpDiagnostics()
    {
        if(_udpDiagnostics is not null && Diagnosing)await _udpDiagnostics.Stop();
        _stage="IDLE";
    }
}
