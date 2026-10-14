namespace OracleProxy.Windows.Preview;

// Standalone deterministic tests: zero OS calls, network access or privileges.
internal static class ControlStateSelfTests
{
    internal static bool Run()
    {
        int passed = 0;
        void Check(bool condition, string caseName)
        {
            if (!condition)
                throw new InvalidOperationException("Control simulation test: " + caseName);
            passed++;
        }

        try
        {
            var controller = new ControlStateSimulator();
            Check(controller.Snapshot().Intent == UserVpnIntent.Unknown, "unknown initial intent");
            Check(!controller.Snapshot().OrdinaryPhysicalDirectAllowed, "unknown fails closed");
            Check(!controller.Snapshot().OrdinaryTunnelAllowed, "unknown no tunnel");
            Check(!controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.DisableVpn, mockCallerAuthorized: false),
                "unauthorized direct request refused");
            Check(controller.Snapshot().Intent == UserVpnIntent.Unknown, "unauthorized cannot change intent");

            Check(controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.EnableVpn, mockCallerAuthorized: true),
                "explicit enable succeeds");
            Check(controller.Snapshot().Intent == UserVpnIntent.Enabled, "enable intent retained");
            Check(!controller.Snapshot().OrdinaryPhysicalDirectAllowed, "connecting blocks direct");

            foreach (SimulatedTunnelPhase state in Enum.GetValues<SimulatedTunnelPhase>())
            {
                foreach (bool handshake in new[] { false, true })
                foreach (bool route in new[] { false, true })
                {
                    controller.ObserveMockTunnel(new(state, handshake, route));
                    bool ready = state == SimulatedTunnelPhase.Connected && handshake && route;
                    var s = controller.Snapshot();
                    Check(s.Intent == UserVpnIntent.Enabled, "observation cannot change intent");
                    Check(s.TunnelReady == ready, "readiness requires verified components");
                    Check(s.OrdinaryTunnelAllowed == ready, "ordinary tunnel gating");
                    Check(!s.OrdinaryPhysicalDirectAllowed, "no physical fallback");

                    foreach (IpFamily family in Enum.GetValues<IpFamily>())
                    foreach (PacketKind packetKind in Enum.GetValues<PacketKind>())
                    {
                        var physical = controller.EvaluateMockFlow(ClientKind.Ordinary,
                            EgressPath.Physical, false, false, family, packetKind);
                        Check(!physical.Allowed, "IPv4/IPv6 TCP/UDP/DNS physical denied");

                        var viaTunnel = controller.EvaluateMockFlow(ClientKind.Ordinary,
                            EgressPath.Tunnel, false, false, family, packetKind);
                        Check(viaTunnel.Allowed == ready, "no tunnel access without health");

                        var uuVerified = controller.EvaluateMockFlow(ClientKind.UuRemote,
                            EgressPath.Physical, true, false, family, packetKind);
                        Check(uuVerified.Allowed, "UU mock verified bypass even while down");
                        var uuUnverified = controller.EvaluateMockFlow(ClientKind.UuRemote,
                            EgressPath.Physical, false, false, family, packetKind);
                        Check(!uuUnverified.Allowed, "UU name alone cannot bypass");
                        passed += 0;
                    }
                }
            }

            controller.SimulateProcessCrash();
            Check(controller.Snapshot().Intent == UserVpnIntent.Enabled, "crash keeps enabled intent");
            Check(!controller.Snapshot().OrdinaryPhysicalDirectAllowed, "crash does not fail open");
            Check(!controller.Snapshot().TunnelReady, "crash resets readiness");

            Check(controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.DisconnectTunnel, true), "disconnect accepted");
            Check(controller.Snapshot().Intent == UserVpnIntent.Enabled,
                "disconnect is not the same as deliberate VPN off");
            Check(!controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.DisableVpn, false), "unauthorized off denied");
            Check(!controller.Snapshot().OrdinaryPhysicalDirectAllowed,
                "unauthorized off cannot restore direct");

            Check(controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.DisableVpn, true), "explicit authorized off");
            Check(controller.Snapshot().OrdinaryPhysicalDirectAllowed,
                "only deliberate off restores direct");
            Check(!controller.Snapshot().OrdinaryTunnelAllowed, "off disables mock tunnel");
            Check(!controller.ApplyMockAuthorizedUserCommand(
                SimulatedUserCommand.Connect, true), "can't connect while explicitly disabled");

            // Model a service restart by re-injecting a previously persisted intent.
            // No actual state persistence or protected storage is implemented.
            var restartedOn = new ControlStateSimulator(UserVpnIntent.Enabled);
            Check(!restartedOn.Snapshot().OrdinaryPhysicalDirectAllowed, "restart-on fails closed");
            var restartedOff = new ControlStateSimulator(UserVpnIntent.ExplicitlyDisabled);
            Check(restartedOff.Snapshot().OrdinaryPhysicalDirectAllowed, "restart-off allows direct");

            // Malformed or unauthorized controls cannot enable direct.
            var rejected = new ControlStateSimulator(UserVpnIntent.Enabled);
            Check(!rejected.ApplyMockAuthorizedUserCommand(
                (SimulatedUserCommand)999, true), "malformed command refused");
            Check(!rejected.Snapshot().OrdinaryPhysicalDirectAllowed, "malformed command retains mode");

            // The mock transport exception is strictly identity + endpoint +
            // IPv4/UDP on physical interface. No unverified generic exception.
            var transport = restartedOn.EvaluateMockFlow(
                ClientKind.VpnEngine, EgressPath.Physical, true, true, IpFamily.IPv4, PacketKind.Udp);
            Check(transport.Allowed, "verified transport mock allowed");
            Check(!restartedOn.EvaluateMockFlow(
                ClientKind.VpnEngine, EgressPath.Physical, true, false, IpFamily.IPv4, PacketKind.Udp).Allowed,
                "unverified endpoint denied");
            Check(!restartedOn.EvaluateMockFlow(
                ClientKind.VpnEngine, EgressPath.Physical, false, true, IpFamily.IPv4, PacketKind.Udp).Allowed,
                "unverified process denied");

            // Pseudonymous test values only; no actual credentials.
            return passed >= 250;
        }
        catch { return false; }
    }
}
