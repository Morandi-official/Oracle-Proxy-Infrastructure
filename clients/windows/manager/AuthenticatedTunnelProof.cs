namespace OracleProxy.LabManager;

// R33: *result* contract for a future real SYSTEM-owned WireGuard probe.
// Only a trusted kernel adapter may construct this from live, independently
// read OS state and a nonce-bound response over the owned tunnel. Never
// deserialize this type from GUI/pipe/JSON, lab statistics, or config files.
//
// A handshake (normally a 92-byte response) is not an application data
// acceptance test. Positive encrypted transfer deltas AND a response to an
// unpredictable, single-use application challenge are required. The real
// adapter must source counters from the *pinned* WireGuard peer, verify the
// return payload/nonce through the owned tunnel, and keep proof fresh to
// the just-started session. This offline predicate does not implement any
// of those OS queries, WFP filters, or challenge traffic.
internal readonly record struct AuthenticatedTunnelProof(
    bool NativeServiceRunning,
    bool FixedSignedPeerConfirmed,
    bool FreshAuthenticatedHandshake,
    bool ProbeSocketBoundToOwnedTunnel,
    bool SingleUseProbeNonceMatched,
    bool OwnedRoutesVerified,
    bool DnsProtectedBySystemWfp,
    long EncryptedTxBefore,
    long EncryptedTxAfter,
    long EncryptedRxBefore,
    long EncryptedRxAfter,
    int EchoRequestsSent,
    int EchoRepliesMatched)
{
    internal bool Verified =>
        NativeServiceRunning &&
        FixedSignedPeerConfirmed &&
        FreshAuthenticatedHandshake &&
        ProbeSocketBoundToOwnedTunnel &&
        SingleUseProbeNonceMatched &&
        OwnedRoutesVerified &&
        DnsProtectedBySystemWfp &&
        EncryptedTxBefore >= 0 &&
        EncryptedRxBefore >= 0 &&
        EncryptedTxAfter > EncryptedTxBefore &&
        EncryptedRxAfter > EncryptedRxBefore &&
        EchoRequestsSent > 0 &&
        EchoRepliesMatched > 0 &&
        EchoRepliesMatched <= EchoRequestsSent;
}
