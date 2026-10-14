namespace OracleProxy.Windows.Preview;

// Pure assertions; no sockets, firewall, registry writes, elevation or VPN.
internal static class PolicySelfTests
{
    internal static bool Run()
    {
        int checks = 0;
        void Check(PolicyInput p, bool allowed, string reason)
        {
            var d = ProtectionPolicy.Evaluate(p);
            if (d.Allowed != allowed || d.Code != reason)
                throw new Exception($"Policy assertion {checks + 1} failed: {d.Code}");
            checks++;
        }

        try
        {
            foreach (IpFamily family in Enum.GetValues<IpFamily>())
            foreach (PacketKind kind in Enum.GetValues<PacketKind>())
            {
                var p = new PolicyInput(VpnIntent.Enabled, TunnelStatus.Connected,
                    true, true, ClientKind.Ordinary, EgressPath.Tunnel,
                    false, false, family, kind);
                Check(p, true, "VERIFIED_TUNNEL_ONLY");
                Check(p with { Egress = EgressPath.Physical }, false, "PHYSICAL_EGRESS_DENIED");

                foreach (TunnelStatus state in new[] {
                    TunnelStatus.Connecting, TunnelStatus.Failed, TunnelStatus.Disconnected
                })
                {
                    Check(p with { Tunnel = state }, false, "TUNNEL_NOT_VERIFIED_READY");
                    Check(p with { Tunnel = state, Egress = EgressPath.Physical },
                        false, "PHYSICAL_EGRESS_DENIED");
                    Check(p with { Tunnel = state, Client = ClientKind.UuRemote,
                        Egress = EgressPath.Physical, IdentityVerified = true },
                        true, "UU_VERIFIED_DIRECT_EXCEPTION");
                }
                Check(p with { HandshakeFresh = false }, false, "TUNNEL_NOT_VERIFIED_READY");
                Check(p with { TunnelRouteVerified = false }, false, "TUNNEL_NOT_VERIFIED_READY");
                Check(p with { Client = ClientKind.UuRemote, Egress = EgressPath.Physical },
                    false, "UU_IDENTITY_UNVERIFIED");
                Check(p with { Client = ClientKind.UuRemote, IdentityVerified = true },
                    false, "UU_TUNNEL_NOT_ALLOWED");
                Check(p with { Client = ClientKind.Unknown, Egress = EgressPath.Physical },
                    false, "PHYSICAL_EGRESS_DENIED");
                Check(p with { Intent = VpnIntent.Disabled, Tunnel = TunnelStatus.Disconnected,
                    Egress = EgressPath.Physical }, true, "USER_EXPLICITLY_DISABLED_VPN");
                Check(p with { Intent = VpnIntent.Disabled }, false, "VPN_NOT_REQUESTED");
            }

            foreach (TunnelStatus state in Enum.GetValues<TunnelStatus>())
            {
                var p = new PolicyInput(VpnIntent.Enabled, state, false, false,
                    ClientKind.VpnEngine, EgressPath.Physical,
                    true, true, IpFamily.IPv4, PacketKind.Udp);
                Check(p, true, "VERIFIED_VPN_TRANSPORT_ONLY");
                Check(p with { IdentityVerified = false }, false, "VPN_TRANSPORT_NOT_VERIFIED");
                Check(p with { EndpointVerified = false }, false, "VPN_TRANSPORT_NOT_VERIFIED");
                Check(p with { Family = IpFamily.IPv6 }, false, "VPN_TRANSPORT_NOT_VERIFIED");
                Check(p with { Kind = PacketKind.Tcp }, false, "VPN_TRANSPORT_NOT_VERIFIED");
                Check(p with { Kind = PacketKind.Dns }, false, "VPN_TRANSPORT_NOT_VERIFIED");
            }
            return checks >= 100;
        }
        catch { return false; }
    }
}
