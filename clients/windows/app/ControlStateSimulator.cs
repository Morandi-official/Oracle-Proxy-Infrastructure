namespace OracleProxy.Windows.Preview;

// W3: PURE SIMULATION. This is NOT a Windows service, identity verifier,
// persistent settings store, WireGuard adapter or network filter.
// Every 'authorization' and 'measurement' is an injected fake for test purposes.
internal enum UserVpnIntent { Unknown, Enabled, ExplicitlyDisabled }
internal enum SimulatedTunnelPhase { Disconnected, Connecting, Connected, Failed }
internal enum SimulatedUserCommand { EnableVpn, DisableVpn, Connect, DisconnectTunnel }

internal sealed record MockTunnelObservation(
    SimulatedTunnelPhase Phase,
    bool FreshHandshake,
    bool VerifiedTunnelPath);

internal sealed record ControlStateSnapshot(
    UserVpnIntent Intent,
    MockTunnelObservation ObservedTunnel,
    bool TunnelReady,
    bool OrdinaryPhysicalDirectAllowed,
    bool OrdinaryTunnelAllowed,
    string Reason);

internal sealed class ControlStateSimulator
{
    // Unknown is intentionally treated as fail-closed in the MODEL.
    // Production boot-time enforcement and durable state storage DO NOT EXIST.
    private UserVpnIntent _intent;
    private MockTunnelObservation _observation =
        new(SimulatedTunnelPhase.Disconnected, false, false);

    internal ControlStateSimulator(UserVpnIntent restoredMockIntent = UserVpnIntent.Unknown)
    {
        if (!Enum.IsDefined(restoredMockIntent))
            throw new ArgumentOutOfRangeException(nameof(restoredMockIntent));
        _intent = restoredMockIntent;
    }

    internal bool ApplyMockAuthorizedUserCommand(
        SimulatedUserCommand command, bool mockCallerAuthorized)
    {
        if (!mockCallerAuthorized)
            return false;

        switch (command)
        {
            case SimulatedUserCommand.EnableVpn:
                _intent = UserVpnIntent.Enabled;
                _observation = new(SimulatedTunnelPhase.Connecting, false, false);
                return true;

            case SimulatedUserCommand.DisableVpn:
                // This is the ONLY supported way to intentionally permit
                // ordinary physical direct egress in the policy model.
                _intent = UserVpnIntent.ExplicitlyDisabled;
                _observation = new(SimulatedTunnelPhase.Disconnected, false, false);
                return true;

            case SimulatedUserCommand.Connect:
                if (_intent != UserVpnIntent.Enabled)
                    return false;
                _observation = new(SimulatedTunnelPhase.Connecting, false, false);
                return true;

            case SimulatedUserCommand.DisconnectTunnel:
                // Disconnect is NOT synonymous with explicit user VPN Off.
                _observation = new(SimulatedTunnelPhase.Disconnected, false, false);
                return true;

            default:
                return false;
        }
    }

    // A tunnel notification is untrusted input in a real implementation:
    // this simulator only tests policy decisions for supplied fake values.
    internal void ObserveMockTunnel(MockTunnelObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (!Enum.IsDefined(observation.Phase))
            throw new ArgumentOutOfRangeException(nameof(observation));
        _observation = observation;
    }

    internal void SimulateProcessCrash()
    {
        // No change to _intent on a crash or driver failure.
        _observation = new(SimulatedTunnelPhase.Failed, false, false);
    }

    internal ControlStateSnapshot Snapshot()
    {
        bool tunnelReady = _intent == UserVpnIntent.Enabled &&
                           _observation.Phase == SimulatedTunnelPhase.Connected &&
                           _observation.FreshHandshake &&
                           _observation.VerifiedTunnelPath;
        bool direct = _intent == UserVpnIntent.ExplicitlyDisabled;
        return new(
            _intent, _observation, tunnelReady,
            OrdinaryPhysicalDirectAllowed: direct,
            OrdinaryTunnelAllowed: tunnelReady,
            Reason: direct ? "EXPLICIT_USER_OFF" :
                    tunnelReady ? "MOCK_TUNNEL_VERIFIED" : "SIMULATED_FAIL_CLOSED");
    }

    internal PolicyDecision EvaluateMockFlow(
        ClientKind client, EgressPath egress, bool mockIdentityVerified,
        bool mockEndpointVerified, IpFamily family, PacketKind packetKind)
    {
        ControlStateSnapshot s = Snapshot();
        // Unknown is deliberately treated the same as Enabled for the
        // fail-closed policy model. Real OS enforcement is NOT connected.
        return ProtectionPolicy.Evaluate(new PolicyInput(
            Intent: s.Intent == UserVpnIntent.ExplicitlyDisabled
                ? VpnIntent.Disabled : VpnIntent.Enabled,
            Tunnel: s.ObservedTunnel.Phase switch
            {
                SimulatedTunnelPhase.Connected => TunnelStatus.Connected,
                SimulatedTunnelPhase.Connecting => TunnelStatus.Connecting,
                SimulatedTunnelPhase.Failed => TunnelStatus.Failed,
                _ => TunnelStatus.Disconnected
            },
            HandshakeFresh: s.TunnelReady,
            TunnelRouteVerified: s.TunnelReady,
            Client: client,
            Egress: egress,
            IdentityVerified: mockIdentityVerified,
            EndpointVerified: mockEndpointVerified,
            Family: family,
            Kind: packetKind));
    }
}
