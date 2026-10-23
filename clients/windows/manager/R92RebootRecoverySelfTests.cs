using System;

namespace OracleProxy.LabManager;

internal static class R92RebootRecoverySelfTests
{
    internal static bool Run()
    {
        try
        {
            int checks = 0;
            void Check(bool value) { if (!value) throw new InvalidOperationException(); checks++; }
            var start = new DateTimeOffset(2026, 10, 18, 1, 0, 0, TimeSpan.Zero);
            var before = new R92BootObservation("ephemeral-owned-vm", "boot-A", start, true);
            var after = before with { BootEpochId = "boot-B",
                ObservationUtc = start.AddMinutes(10) };
            var complete = new R92PostBootEvidence(
                true, true, true, true, true, true, true, true, true);
            void Denied(R92RebootAssessment outcome, R92RebootVerdict expected)
            {
                Check(outcome.Verdict == expected);
                Check(!outcome.MayConnect && !outcome.MayReleaseWfp);
                Check(!outcome.MayChangeRoutesDns && !outcome.MayPublishInstaller);
                Check(!outcome.PhysicalFieldApproved);
                Check(outcome.Code.EndsWith("_DENY", StringComparison.Ordinal));
            }
            Denied(R92RebootRecoveryGate.Evaluate(before, before with {
                    ObservationUtc = start.AddMinutes(10) }, complete),
                R92RebootVerdict.NoRealRebootObserved);
            Denied(R92RebootRecoveryGate.Evaluate(before, after, complete),
                R92RebootVerdict.ExternalAttestationReviewRequired);
            Denied(R92RebootRecoveryGate.Evaluate(before, after with {
                    MachineId = "other-or-untrusted-vm" }, complete),
                R92RebootVerdict.MalformedEvidence);
            Denied(R92RebootRecoveryGate.Evaluate(before, after with {
                    ObservationUtc = start.AddMinutes(-1) }, complete),
                R92RebootVerdict.MalformedEvidence);
            Denied(R92RebootRecoveryGate.Evaluate(before, after with {
                    ObservationUtc = start.AddDays(8) }, complete),
                R92RebootVerdict.MalformedEvidence);
            Denied(R92RebootRecoveryGate.Evaluate(before with {
                    OsBootIdentityIndependentlyRecorded = false }, after, complete),
                R92RebootVerdict.MalformedEvidence);
            Denied(R92RebootRecoveryGate.Evaluate(before with {
                    BootEpochId = "" }, after, complete),
                R92RebootVerdict.MalformedEvidence);
            Denied(R92RebootRecoveryGate.Evaluate(before, after with {
                    ObservationUtc = after.ObservationUtc.ToOffset(TimeSpan.FromHours(9))
                }, complete), R92RebootVerdict.MalformedEvidence);

            var missing = new[] {
                complete with { IndependentConsoleAndSnapshotRestoreDemonstrated = false },
                complete with { PreLoginNativeWfpIpv4Ipv6TcpUdpDnsPacketCaptureVerified = false },
                complete with { NativeTunnelSafeStopIndependentlyVerified = false },
                complete with { SystemOwnedRecoveryTaskAndSignerVerified = false },
                complete with { ExactOwnedFilesServicesRoutesDnsCleanupVerified = false },
                complete with { UuRemoteSessionContinuityVerified = false },
                complete with { ThirdPartyWireSockAndUuSettingsUntouched = false },
                complete with { DetachedNetworkAndKeysRevoked = false },
                complete with { IndependentWitnessAttestationProvided = false }
            };
            foreach (var item in missing)
            {
                var expected = (!item.IndependentConsoleAndSnapshotRestoreDemonstrated ||
                                !item.IndependentWitnessAttestationProvided)
                    ? R92RebootVerdict.UncorroboratedBootChange
                    : R92RebootVerdict.MissingCriticalEvidence;
                Denied(R92RebootRecoveryGate.Evaluate(before, after, item), expected);
            }
            Check(!new R92RebootAssessment(
                R92RebootVerdict.ExternalAttestationReviewRequired).MayConnect);
            Console.WriteLine("R92_REAL_REBOOT_EVIDENCE_DENY_ONLY_NEGATIVE_MATRIX_PASS=" + checks);
            Console.WriteLine("R92_ACTUAL_WINDOWS_REBOOT_PERFORMED=false");
            Console.WriteLine("R92_REAL_REBOOT_FIELD_ACCEPTANCE_GRANTED=false");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R92_REBOOT_EVIDENCE_TEST_FAIL");
            return false;
        }
    }
}
