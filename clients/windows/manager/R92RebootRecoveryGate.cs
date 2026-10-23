using System;

namespace OracleProxy.LabManager;

// R92: OFFLINE evidence model for an eventual *real* reboot of a disposable,
// noncritical Windows VM with independent out-of-band console and rollback.
// User/CI JSON, Task Scheduler LastRunTime, a timestamp or environment flags
// are NOT trusted external attestation. No WFP/SCM/DNS/route operations here.
internal readonly record struct R92BootObservation(
    string MachineId,
    string BootEpochId,
    DateTimeOffset ObservationUtc,
    bool OsBootIdentityIndependentlyRecorded)
{
    internal bool ShapeValid =>
        !string.IsNullOrWhiteSpace(MachineId) && MachineId.Length <= 128 &&
        !string.IsNullOrWhiteSpace(BootEpochId) && BootEpochId.Length <= 128 &&
        ObservationUtc.Offset == TimeSpan.Zero &&
        OsBootIdentityIndependentlyRecorded;
}

internal readonly record struct R92PostBootEvidence(
    bool IndependentConsoleAndSnapshotRestoreDemonstrated,
    bool PreLoginNativeWfpIpv4Ipv6TcpUdpDnsPacketCaptureVerified,
    bool NativeTunnelSafeStopIndependentlyVerified,
    bool SystemOwnedRecoveryTaskAndSignerVerified,
    bool ExactOwnedFilesServicesRoutesDnsCleanupVerified,
    bool UuRemoteSessionContinuityVerified,
    bool ThirdPartyWireSockAndUuSettingsUntouched,
    bool DetachedNetworkAndKeysRevoked,
    bool IndependentWitnessAttestationProvided)
{
    internal bool AllClaimed =>
        IndependentConsoleAndSnapshotRestoreDemonstrated &&
        PreLoginNativeWfpIpv4Ipv6TcpUdpDnsPacketCaptureVerified &&
        NativeTunnelSafeStopIndependentlyVerified &&
        SystemOwnedRecoveryTaskAndSignerVerified &&
        ExactOwnedFilesServicesRoutesDnsCleanupVerified &&
        UuRemoteSessionContinuityVerified &&
        ThirdPartyWireSockAndUuSettingsUntouched &&
        DetachedNetworkAndKeysRevoked &&
        IndependentWitnessAttestationProvided;
}

internal enum R92RebootVerdict
{
    MalformedEvidence,
    NoRealRebootObserved,
    UncorroboratedBootChange,
    MissingCriticalEvidence,
    ExternalAttestationReviewRequired
}

internal readonly record struct R92RebootAssessment(R92RebootVerdict Verdict)
{
    // Deliberately no positive release or OS mutation path even for
    // self-asserted "all green" JSON. Out-of-band cert and packet evidence
    // MUST be independently reviewed outside this executable.
    internal bool MayConnect => false;
    internal bool MayReleaseWfp => false;
    internal bool MayChangeRoutesDns => false;
    internal bool MayPublishInstaller => false;
    internal bool PhysicalFieldApproved => false;

    internal string Code => Verdict switch
    {
        R92RebootVerdict.MalformedEvidence => "R92_REBOOT_EVIDENCE_MALFORMED_DENY",
        R92RebootVerdict.NoRealRebootObserved => "R92_SAME_BOOT_NOT_A_REBOOT_DENY",
        R92RebootVerdict.UncorroboratedBootChange => "R92_BOOT_CHANGE_UNCORROBORATED_DENY",
        R92RebootVerdict.MissingCriticalEvidence => "R92_REBOOT_CRITICAL_PROOFS_MISSING_DENY",
        _ => "R92_EXTERNAL_ATTESTATION_AND_HUMAN_REVIEW_REQUIRED_DENY"
    };
}

internal static class R92RebootRecoveryGate
{
    internal static R92RebootAssessment Evaluate(
        R92BootObservation before,
        R92BootObservation after,
        R92PostBootEvidence claims)
    {
        if (!before.ShapeValid || !after.ShapeValid ||
            !string.Equals(before.MachineId, after.MachineId, StringComparison.Ordinal) ||
            before.ObservationUtc >= after.ObservationUtc ||
            (after.ObservationUtc - before.ObservationUtc) > TimeSpan.FromDays(7))
            return new(R92RebootVerdict.MalformedEvidence);
        if (string.Equals(before.BootEpochId, after.BootEpochId, StringComparison.Ordinal))
            return new(R92RebootVerdict.NoRealRebootObserved);
        // Even different self-declared boot IDs are not a trustworthy OS
        // restart proof. The external controller must attest distinct boots.
        if (!claims.IndependentConsoleAndSnapshotRestoreDemonstrated ||
            !claims.IndependentWitnessAttestationProvided)
            return new(R92RebootVerdict.UncorroboratedBootChange);
        if (!claims.AllClaimed)
            return new(R92RebootVerdict.MissingCriticalEvidence);
        return new(R92RebootVerdict.ExternalAttestationReviewRequired);
    }
}
