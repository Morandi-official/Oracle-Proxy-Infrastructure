namespace OracleProxy.LabManager;

// R36: startup recovery gate for a *future* durable SYSTEM adapter.
// These are independent facts, never copied from GUI, IPC or a disk journal.
// A ledger claiming Off or Connected is never proof of live OS safety.
internal enum DurableStartupPhase
{
    Missing,
    CorruptOrUntrusted,
    ConnectPrepared,
    ConnectedRecorded,
    DisconnectPrepared,
    OffRecordedNeedsOsAudit
}

internal readonly record struct StartupRecoveryEvidence(
    DurableStartupPhase JournalPhase,
    bool SignedProfileAndServiceVerified,
    bool PinnedPeerAndProtectedKeyVerified,
    bool PersistentAllDeviceWfpVerified,
    bool NativeTunnelStateIndependentlyVerified,
    bool OwnedRoutesAndDnsIndependentlyVerified,
    bool CurrentUserAuthorizationVerified)
{
    // There is deliberately no automatic startup admission here. In particular:
    // recorded Off must not remove WFP, and recorded Connected must not auto-connect.
    internal bool AllowAutomaticConnect => false;
    internal bool AllowAutomaticWfpRelease => false;
    internal bool AllowUnattendedDirectNetworking => false;

    internal bool NeedsOutOfBandRecovery =>
        JournalPhase is DurableStartupPhase.Missing or
            DurableStartupPhase.CorruptOrUntrusted or
            DurableStartupPhase.ConnectPrepared or
            DurableStartupPhase.DisconnectPrepared ||
        !PersistentAllDeviceWfpVerified ||
        !SignedProfileAndServiceVerified ||
        !PinnedPeerAndProtectedKeyVerified ||
        !NativeTunnelStateIndependentlyVerified ||
        !OwnedRoutesAndDnsIndependentlyVerified ||
        !CurrentUserAuthorizationVerified;

    internal string ResultCode => NeedsOutOfBandRecovery
        ? "STARTUP_RECOVERY_REQUIRED"
        : "STARTUP_OS_AUDIT_ONLY_NO_AUTOMATIC_ACTION";
}

internal static class SystemStartupRecoveryBoundary
{
    // The actual manager may request this conservative snapshot before pipes
    // start. No file reads, automatic key decrypt, WFP removal or SCM mutation.
    internal static StartupRecoveryEvidence ReadConservativeBaseline()
    {
        var wfp = NativeWfpReadOnlyAudit.Read();
        // BFE availability is NOT comprehensive all-device WFP coverage.
        _ = wfp;
        return new StartupRecoveryEvidence(DurableStartupPhase.Missing,
            false, false, false, false, false, false);
    }
}
