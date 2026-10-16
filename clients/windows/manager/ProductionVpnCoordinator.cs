using System.Security.Cryptography;

namespace OracleProxy.LabManager;

// R27: transaction contract, not a production implementation. The REAL
// default kernel is a permanent deny-only adapter. Never accept caller JSON
// as OS WFP evidence, a key, an endpoint, a service name or an off receipt.
internal readonly record struct WfpCoverage(
    bool SystemOwned, bool Persistent, bool PhysicalIpv4, bool PhysicalIpv6,
    bool Tcp, bool Udp, bool SystemDns, bool Multihomed,
    bool BootAndPreLogin, bool CrashSafe, bool EndpointExceptionAudited,
    bool RemoteControlExceptionAudited)
{
    internal bool AllVerified =>
        SystemOwned && Persistent && PhysicalIpv4 && PhysicalIpv6 &&
        Tcp && Udp && SystemDns && Multihomed && BootAndPreLogin &&
        CrashSafe && EndpointExceptionAudited && RemoteControlExceptionAudited;
}

internal interface IProductionVpnKernel
{
    // Implementations must independently query OS-owned WFP filters, not
    // use profile JSON or the process-scoped R21-R26 CI policy as evidence.
    WfpCoverage AuditExistingSystemWfp();
    EgressInterfaceCoverage AuditEgressInterfaceCoverage();
    bool VerifyPinnedSignedTunnel();
    ProtectedKeyLease OpenProtectedPeerKey();
    void StartFixedTunnel(ReadOnlySpan<byte> privateKey);
    AuthenticatedTunnelProof ReadAuthenticatedTunnelProof();
    void StopFixedTunnel();
    bool VerifyTunnelStopped();
    bool StageOwnedRouteDnsRecovery();
    bool PersistExplicitOffIntent();
    bool ReleaseOnlyOwnedWfp();
    bool VerifyDirectNetworkRestored();
    // Compensating best-effort protection after an ambiguous or failed release.
    // Must only touch independently owned OS policy. Never a release or connect.
    bool TryReestablishOwnedWfpGuard();
}

// A lease owns precisely 32 decrypted bytes, with no plaintext file or
// logging. The eventual DPAPI-backed SYSTEM implementation must supply it.
// Zeroing is necessary but not sufficient for managed-memory confidentiality.
internal sealed class ProtectedKeyLease : IDisposable
{
    private byte[]? _key;
    internal ProtectedKeyLease(byte[] decrypted)
    {
        if (decrypted is null || decrypted.Length != 32)
            throw new ArgumentException("A WireGuard private key is exactly 32 bytes");
        _key = decrypted;
    }
    internal ReadOnlySpan<byte> Bytes => _key ??
        throw new ObjectDisposedException(nameof(ProtectedKeyLease));
    public void Dispose()
    {
        if (_key is { } key)
        {
            CryptographicOperations.ZeroMemory(key);
            _key = null;
        }
    }
}

// Deliberately the ONLY production backend installed by the actual SYSTEM
// service. Cannot start a tunnel, decrypt a key or release a WFP rule.
internal sealed class UnavailableProductionKernel : IProductionVpnKernel
{
    public WfpCoverage AuditExistingSystemWfp() => default;
    public EgressInterfaceCoverage AuditEgressInterfaceCoverage() => default;
    public bool VerifyPinnedSignedTunnel() => false;
    public ProtectedKeyLease OpenProtectedPeerKey() =>
        throw new InvalidOperationException("Protected SYSTEM key adapter unavailable");
    public void StartFixedTunnel(ReadOnlySpan<byte> privateKey) =>
        throw new InvalidOperationException("Production tunnel unavailable");
    public AuthenticatedTunnelProof ReadAuthenticatedTunnelProof() => default;
    public void StopFixedTunnel() { }
    public bool VerifyTunnelStopped() => false;
    public bool StageOwnedRouteDnsRecovery() => false;
    public bool PersistExplicitOffIntent() => false;
    public bool ReleaseOnlyOwnedWfp() => false;
    public bool VerifyDirectNetworkRestored() => false;
    public bool TryReestablishOwnedWfpGuard() => false;
}

internal enum ProductionTunnelState
{
    UnknownFailClosed, ProtectedDisconnected, Connected,
    DisconnectPending, RecoveryRequired
}

internal sealed class ProductionVpnCoordinator
{
    private readonly IProductionVpnKernel _kernel;
    private readonly object _sync = new();
    private ProductionTunnelState _state = ProductionTunnelState.UnknownFailClosed;
    private bool _locked;

    internal ProductionVpnCoordinator(IProductionVpnKernel kernel) =>
        _kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
    internal ProductionTunnelState State { get { lock (_sync) return _state; } }

    internal string Connect()
    {
        lock (_sync)
        {
            if (_locked || _state is ProductionTunnelState.DisconnectPending or
                ProductionTunnelState.RecoveryRequired)
                return "RECOVERY_REQUIRED";
            if (_state == ProductionTunnelState.Connected)
                return "ALREADY_CONNECTED";
            try
            {
                // No OS operations until ALL required evidence is established.
                if (!_kernel.AuditExistingSystemWfp().AllVerified)
                    return "WFP_FAIL_CLOSED_NOT_IMPLEMENTED";
                if (!_kernel.AuditEgressInterfaceCoverage().Verified)
                    return "EGRESS_INTERFACE_SCOPE_NOT_VERIFIED";
                if (!_kernel.VerifyPinnedSignedTunnel())
                    return "TUNNEL_TRUST_NOT_VERIFIED";
                using var lease = _kernel.OpenProtectedPeerKey();
                _state = ProductionTunnelState.ProtectedDisconnected;
                _kernel.StartFixedTunnel(lease.Bytes);
                if (!_kernel.ReadAuthenticatedTunnelProof().Verified)
                    throw new InvalidOperationException("No authenticated in-tunnel data proof");
                if (!_kernel.AuditExistingSystemWfp().AllVerified ||
                    !_kernel.AuditEgressInterfaceCoverage().Verified)
                    throw new InvalidOperationException("WFP or interface scope lost during startup");
                _state = ProductionTunnelState.Connected;
                return "CONNECTED_VERIFIED";
            }
            catch
            {
                _locked = true;
                _state = ProductionTunnelState.RecoveryRequired;
                try { _kernel.StopFixedTunnel(); } catch { /* stay fail-closed */ }
                // Never release WFP automatically after a failed start.
                return "CONNECT_FAILED_LOCKED";
            }
        }
    }

    internal string ExplicitDisconnect()
    {
        lock (_sync)
        {
            if (_locked || _state != ProductionTunnelState.Connected)
                return "DISCONNECT_REQUIRES_RECOVERY";
            _state = ProductionTunnelState.DisconnectPending;
            bool releaseAttempted = false;
            try
            {
                // The OS guard remains active until the tunnel has stopped,
                // owned networking is staged for restoration and explicit Off
                // is DURABLY committed. Failure never calls WFP release.
                _kernel.StopFixedTunnel();
                if (!_kernel.VerifyTunnelStopped() ||
                    !_kernel.AuditExistingSystemWfp().AllVerified ||
                    !_kernel.AuditEgressInterfaceCoverage().Verified ||
                    !_kernel.StageOwnedRouteDnsRecovery() ||
                    !_kernel.PersistExplicitOffIntent())
                    throw new InvalidOperationException("Unsafe disconnect precondition");
                // Re-audit immediately before the irreversible owned-filter
                // release. This narrows the stale-evidence interval but is
                // NOT atomic with WFP and is not a production implementation.
                if (!_kernel.AuditExistingSystemWfp().AllVerified ||
                    !_kernel.AuditEgressInterfaceCoverage().Verified)
                    throw new InvalidOperationException("WFP/interface scope changed before release");
                releaseAttempted = true; // even an exception/false can mean partial release
                if (!_kernel.ReleaseOnlyOwnedWfp() ||
                    !_kernel.VerifyDirectNetworkRestored())
                    throw new InvalidOperationException("Unsafe network release");
                // A future production adapter also needs atomic crash
                // recovery and out-of-band rescue; this is a model only.
                _state = ProductionTunnelState.UnknownFailClosed;
                return "DISCONNECTED_VERIFIED";
            }
            catch
            {
                _locked = true;
                _state = ProductionTunnelState.RecoveryRequired;
                if (releaseAttempted)
                {
                    // A failed/ambiguous WFP release is not a safe Off. Try to
                    // re-establish ONLY this app's owned guard, never auto
                    // reconnect, never report restored or clear the latch.
                    // The kernel must independently audit ownership and OS
                    // policy before implementing any mutation. Failure here
                    // still requires out-of-band recovery and may have leaked.
                    try
                    {
                        if (_kernel.TryReestablishOwnedWfpGuard())
                            _ = _kernel.AuditExistingSystemWfp().AllVerified;
                    }
                    catch { /* retain hard recovery requirement */ }
                }
                return "DISCONNECT_FAILED_LOCKED";
            }
        }
    }
}
