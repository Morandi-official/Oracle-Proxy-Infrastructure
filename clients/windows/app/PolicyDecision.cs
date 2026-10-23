namespace OracleProxy.Windows.Preview;

// Side-effect-free preview of future enforcement intent; NEVER a real firewall.
internal enum VpnIntent { Enabled, Disabled }
internal enum TunnelStatus { Connected, Connecting, Failed, Disconnected }
internal enum ClientKind { UuRemote, VpnEngine, Ordinary, Unknown }
internal enum EgressPath { Physical, Tunnel }
internal enum IpFamily { IPv4, IPv6 }
internal enum PacketKind { Tcp, Udp, Dns }

internal sealed record PolicyInput(
    VpnIntent Intent,
    TunnelStatus Tunnel,
    bool HandshakeFresh,
    bool TunnelRouteVerified,
    ClientKind Client,
    EgressPath Egress,
    bool IdentityVerified,
    bool EndpointVerified,
    IpFamily Family,
    PacketKind Kind
);

internal sealed record PolicyDecision(bool Allowed, string Code, string SimulatedState);

internal static class ProtectionPolicy
{
    public static PolicyDecision Evaluate(PolicyInput input)
    {
        if (input.Intent == VpnIntent.Disabled)
        {
            return input.Egress == EgressPath.Physical
                ? new(true, "USER_EXPLICITLY_DISABLED_VPN", "DeliberateDirectMode")
                : new(false, "VPN_NOT_REQUESTED", "DeliberateDirectMode");
        }

        bool healthy = input.Tunnel == TunnelStatus.Connected &&
                       input.HandshakeFresh && input.TunnelRouteVerified;
        string state = healthy ? "SimulatedTunnelReady" : "SimulatedFailClosed";

        if (input.Client == ClientKind.UuRemote)
        {
            if (!input.IdentityVerified)
                return new(false, "UU_IDENTITY_UNVERIFIED", state);
            if (input.Egress != EgressPath.Physical)
                return new(false, "UU_TUNNEL_NOT_ALLOWED", state);
            return new(true, "UU_VERIFIED_DIRECT_EXCEPTION", state);
        }

        if (input.Client == ClientKind.VpnEngine)
        {
            bool permitted = input.IdentityVerified &&
                             input.EndpointVerified &&
                             input.Egress == EgressPath.Physical &&
                             input.Family == IpFamily.IPv4 &&
                             input.Kind == PacketKind.Udp;
            return permitted
                ? new(true, "VERIFIED_VPN_TRANSPORT_ONLY", state)
                : new(false, "VPN_TRANSPORT_NOT_VERIFIED", state);
        }

        if (input.Egress == EgressPath.Physical)
            return new(false, "PHYSICAL_EGRESS_DENIED", state);
        if (!healthy)
            return new(false, "TUNNEL_NOT_VERIFIED_READY", state);
        return new(true, "VERIFIED_TUNNEL_ONLY", state);
    }
}
