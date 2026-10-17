namespace OracleProxy.LabManager;

// R62: a strictly negative production admission contract, NOT an installed
// UU exception or route. Neither a process name, executable filename,
// hard-coded vendor IP, GUI claim nor remote-session indicator is evidence.
// A future signed SYSTEM kernel MUST derive all fields from independent OS
// observations and attended, independently recoverable physical testing.
internal readonly record struct RemoteControlContinuityEvidence(
    bool IndependentOsSessionInventory,
    bool SignedImagePathAndTokenIdentityVerified,
    bool ActiveTransportAndEndpointInventoryComplete,
    bool Ipv4TcpUdpDirectContinuityProven,
    bool Ipv6TcpUdpDirectContinuityProven,
    bool DnsAndDynamicEndpointPolicyVerified,
    bool NoUnclassifiedOrUnknownRemoteFlows,
    bool VpnUnderlayIsolationVerified,
    bool OutOfBandRecoveryVerified,
    bool LiveReconnectionUnderFailureVerified)
{
    // No default, partial or self-reported measurement ever authorizes a
    // tunnel start or WFP release. Includes UU and OTHER remote-control tools.
    internal bool Verified =>
        IndependentOsSessionInventory &&
        SignedImagePathAndTokenIdentityVerified &&
        ActiveTransportAndEndpointInventoryComplete &&
        Ipv4TcpUdpDirectContinuityProven &&
        Ipv6TcpUdpDirectContinuityProven &&
        DnsAndDynamicEndpointPolicyVerified &&
        NoUnclassifiedOrUnknownRemoteFlows &&
        VpnUnderlayIsolationVerified &&
        OutOfBandRecoveryVerified &&
        LiveReconnectionUnderFailureVerified;
}
