namespace OracleProxy.LabManager;

internal static class SystemStartupRecoveryBoundarySelfTests
{
    internal static bool Run()
    {
        try
        {
            int count = 0;
            void Check(bool ok) { if (!ok) throw new InvalidOperationException(); count++; }
            var baseline = SystemStartupRecoveryBoundary.ReadConservativeBaseline();
            Check(baseline.NeedsOutOfBandRecovery);
            Check(baseline.ResultCode == "STARTUP_RECOVERY_REQUIRED");
            foreach (DurableStartupPhase phase in Enum.GetValues<DurableStartupPhase>())
            {
                var all = new StartupRecoveryEvidence(phase, true, true,
                    true, true, true, true);
                Check(!all.AllowAutomaticConnect);
                Check(!all.AllowAutomaticWfpRelease);
                Check(!all.AllowUnattendedDirectNetworking);
                if (phase is DurableStartupPhase.ConnectedRecorded or
                    DurableStartupPhase.OffRecordedNeedsOsAudit)
                    Check(!all.NeedsOutOfBandRecovery &&
                        all.ResultCode == "STARTUP_OS_AUDIT_ONLY_NO_AUTOMATIC_ACTION");
                else
                    Check(all.NeedsOutOfBandRecovery);
                for (int missing = 0; missing < 6; missing++)
                {
                    var bad = all with
                    {
                        SignedProfileAndServiceVerified = missing != 0,
                        PinnedPeerAndProtectedKeyVerified = missing != 1,
                        PersistentAllDeviceWfpVerified = missing != 2,
                        NativeTunnelStateIndependentlyVerified = missing != 3,
                        OwnedRoutesAndDnsIndependentlyVerified = missing != 4,
                        CurrentUserAuthorizationVerified = missing != 5
                    };
                    Check(bad.NeedsOutOfBandRecovery);
                    Check(!bad.AllowAutomaticWfpRelease);
                    Check(!bad.AllowAutomaticConnect);
                }
            }
            Console.WriteLine("R36_STARTUP_RECOVERY_BOUNDARY_PASS: " + count +
                " no automatic WFP release/connect even with claimed Off, no OS mutation");
            return true;
        }
        catch
        {
            Console.Error.WriteLine("R36_STARTUP_RECOVERY_BOUNDARY_FAIL");
            return false;
        }
    }
}
