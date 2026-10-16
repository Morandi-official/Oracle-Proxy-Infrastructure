using System.Security.Cryptography;

namespace OracleProxy.LabManager;

internal static class ProductionVpnCoordinatorSelfTests
{
    private sealed class FakeKernel : IProductionVpnKernel
    {
        internal readonly List<string> Calls = new();
        internal string? FailAt;
        internal int FailWfpOnAuditNumber;
        internal int FailEgressOnAuditNumber;
        private int _egressAudits;
        internal bool ReprotectThrows;
        private int _wfpAudits;
        internal byte[]? Secret;
        private bool Check(string step)
        {
            Calls.Add(step);
            return step != FailAt;
        }
        public WfpCoverage AuditExistingSystemWfp()
        {
            _wfpAudits++;
            bool valid = Check("Wfp") &&
                (FailWfpOnAuditNumber == 0 || _wfpAudits != FailWfpOnAuditNumber);
            return new WfpCoverage(valid, valid, valid, valid, valid, valid,
                valid, valid, valid, valid, valid, valid);
        }
        public EgressInterfaceCoverage AuditEgressInterfaceCoverage()
        {
            _egressAudits++;
            bool valid = Check("Egress") &&
                (FailEgressOnAuditNumber == 0 ||
                 _egressAudits != FailEgressOnAuditNumber);
            return new EgressInterfaceCoverage(valid, valid, valid,
                valid, valid, new int[] { 10 }, new int[] { 10 },
                new int[] { 10, 11 }, new int[] { 10, 11 });
        }
        public bool VerifyPinnedSignedTunnel() => Check("Trust");
        public ProtectedKeyLease OpenProtectedPeerKey()
        {
            if (!Check("Unseal")) throw new CryptographicException();
            Secret = RandomNumberGenerator.GetBytes(32);
            return new ProtectedKeyLease(Secret);
        }
        public void StartFixedTunnel(ReadOnlySpan<byte> secret)
        {
            if (secret.Length != 32 || !Check("Start"))
                throw new InvalidOperationException();
        }
        public AuthenticatedTunnelProof ReadAuthenticatedTunnelProof()
        {
            bool valid = Check("Handshake");
            return new AuthenticatedTunnelProof(true, true, valid, true, valid,
                true, true, 100, valid ? 200 : 100, 200,
                valid ? 300 : 200, 1, valid ? 1 : 0);
        }
        public void StopFixedTunnel() { if (!Check("Stop")) throw new InvalidOperationException(); }
        public bool VerifyTunnelStopped() => Check("Stopped");
        public bool StageOwnedRouteDnsRecovery() => Check("RestoreStage");
        public bool PersistExplicitOffIntent() => Check("OffDurable");
        public bool ReleaseOnlyOwnedWfp() => Check("Release");
        public bool VerifyDirectNetworkRestored() => Check("Direct");
        public bool TryReestablishOwnedWfpGuard()
        {
            if (ReprotectThrows) { Calls.Add("Reprotect"); throw new InvalidOperationException(); }
            return Check("Reprotect");
        }
    }

    internal static bool Run()
    {
        int assertions = 0;
        void Check(bool ok)
        {
            if (!ok) throw new InvalidOperationException("R27 assertion " + assertions);
            assertions++;
        }
        try
        {
            var production = new ProductionVpnCoordinator(new UnavailableProductionKernel());
            Check(production.State == ProductionTunnelState.UnknownFailClosed);
            Check(production.Connect() == "WFP_FAIL_CLOSED_NOT_IMPLEMENTED");
            Check(production.ExplicitDisconnect() == "DISCONNECT_REQUIRES_RECOVERY");
            Check(production.State == ProductionTunnelState.UnknownFailClosed);

            // Insufficient *one* dimension must reject prior to decrypt/start.
            var all = new WfpCoverage(true,true,true,true,true,true,true,true,
                true,true,true,false);
            Check(!all.AllVerified);
            foreach (var failedStep in new [] {"Wfp","Egress","Trust","Unseal","Start","Handshake"})
            {
                var fake = new FakeKernel { FailAt = failedStep };
                var tx = new ProductionVpnCoordinator(fake);
                string code = tx.Connect();
                if (failedStep is "Wfp" or "Egress" or "Trust")
                {
                    Check(code is "WFP_FAIL_CLOSED_NOT_IMPLEMENTED" or
                        "EGRESS_INTERFACE_SCOPE_NOT_VERIFIED" or
                        "TUNNEL_TRUST_NOT_VERIFIED");
                    Check(!fake.Calls.Contains("Unseal"));
                    Check(!fake.Calls.Contains("Start"));
                }
                else
                {
                    Check(code == "CONNECT_FAILED_LOCKED");
                    Check(fake.Calls.Contains("Stop"));
                    Check(!fake.Calls.Contains("Release"));
                    Check(tx.Connect() == "RECOVERY_REQUIRED");
                    Check(tx.ExplicitDisconnect() == "DISCONNECT_REQUIRES_RECOVERY");
                }
                if (fake.Secret is not null)
                    Check(fake.Secret.All(b => b == 0));
            }
            foreach (var fail in new [] {"Stop","Stopped","Wfp","Egress","RestoreStage",
                                       "OffDurable","Release","Direct"})
            {
                var fake = new FakeKernel();
                var tx = new ProductionVpnCoordinator(fake);
                Check(tx.Connect() == "CONNECTED_VERIFIED");
                Check(fake.Secret is not null && fake.Secret.All(b => b == 0));
                fake.FailAt = fail;
                fake.Calls.Clear();
                Check(tx.ExplicitDisconnect() == "DISCONNECT_FAILED_LOCKED");
                if (fail is "Stop" or "Stopped" or "Wfp" or "Egress" or
                    "RestoreStage" or "OffDurable")
                {
                    Check(!fake.Calls.Contains("Release"));
                    Check(!fake.Calls.Contains("Reprotect"));
                }
                else
                {
                    Check(fake.Calls.Contains("Reprotect"));
                    Check(fake.Calls.IndexOf("Release") < fake.Calls.IndexOf("Reprotect"));
                }
                Check(tx.Connect() == "RECOVERY_REQUIRED");
            }
            // Audit #1 before Start, #2 after challenge, #3 during Off
            // preparation, #4 immediately before WFP release. No release
            // may run if the OS evidence changes at the last moment.
            var tamperedBeforeRelease = new FakeKernel { FailWfpOnAuditNumber = 4 };
            var guardedOff = new ProductionVpnCoordinator(tamperedBeforeRelease);
            Check(guardedOff.Connect() == "CONNECTED_VERIFIED");
            tamperedBeforeRelease.Calls.Clear();
            Check(guardedOff.ExplicitDisconnect() == "DISCONNECT_FAILED_LOCKED");
            Check(!tamperedBeforeRelease.Calls.Contains("Release"));
            Check(tamperedBeforeRelease.Calls.Contains("OffDurable"));
            Check(guardedOff.State == ProductionTunnelState.RecoveryRequired);
            Check(guardedOff.Connect() == "RECOVERY_REQUIRED");
            Check(guardedOff.ExplicitDisconnect() == "DISCONNECT_REQUIRES_RECOVERY");
            // Even if best-effort re-protection throws, never claim safe Off.
            var unrecoverable = new FakeKernel { ReprotectThrows = true };
            var uncertain = new ProductionVpnCoordinator(unrecoverable);
            Check(uncertain.Connect() == "CONNECTED_VERIFIED");
            unrecoverable.FailAt = "Direct";
            unrecoverable.Calls.Clear();
            Check(uncertain.ExplicitDisconnect() == "DISCONNECT_FAILED_LOCKED");
            Check(unrecoverable.Calls.Contains("Reprotect"));
            Check(uncertain.State == ProductionTunnelState.RecoveryRequired);
            Check(uncertain.Connect() == "RECOVERY_REQUIRED");
            Check(uncertain.ExplicitDisconnect() == "DISCONNECT_REQUIRES_RECOVERY");

            // Dynamic route/adapter churn after connect but before Off
            // must not trigger release, even when WFP itself is unchanged.
            var movedEgress = new FakeKernel { FailEgressOnAuditNumber = 4 };
            var guardedRoute = new ProductionVpnCoordinator(movedEgress);
            Check(guardedRoute.Connect() == "CONNECTED_VERIFIED");
            movedEgress.Calls.Clear();
            Check(guardedRoute.ExplicitDisconnect() == "DISCONNECT_FAILED_LOCKED");
            Check(!movedEgress.Calls.Contains("Release"));
            Check(!movedEgress.Calls.Contains("Reprotect"));
            Check(movedEgress.Calls.Contains("OffDurable"));
            Check(guardedRoute.State == ProductionTunnelState.RecoveryRequired);

            // Synthetic NICs: exact indices, not the count (1,0,1,1),
            // determine whether existing WFP guards cover every route.
            var validEgress = new EgressInterfaceCoverage(true,true,true,true,true,
                new int[] { 7 }, new int[] { 7 }, new int[] { 7 }, new int[] { 7 });
            Check(validEgress.Verified);
            Check(!(validEgress with {
                Ipv4DefaultRouteInterfaceIndexes = new int[] { 7, 8 } }).Verified);
            Check(!(validEgress with {
                Ipv6DefaultRouteInterfaceIndexes = new int[] { 7, 9 } }).Verified);
            Check(!(validEgress with { AllUpInterfacesEnumerated = false }).Verified);
            Check(!(validEgress with { UnknownOrUnclassifiedEgressAbsent = false }).Verified);
            Check(!(validEgress with { AllInterfaceDnsProtected = false }).Verified);
            Check(!(validEgress with { CurrentSessionSnapshot = false }).Verified);
            Check(!(validEgress with { IndependentOsSnapshot = false }).Verified);
            Check(!(validEgress with {
                Ipv4DefaultRouteInterfaceIndexes = new int[] { 7, 7 } }).Verified);
            Check(!(validEgress with {
                GuardedIpv6InterfaceIndexes = new int[] { 0, 7 } }).Verified);
            Check(!(validEgress with {
                Ipv6DefaultRouteInterfaceIndexes = Array.Empty<int>() }).Verified);
            Check(!default(EgressInterfaceCoverage).Verified);

            var successful = new FakeKernel();
            var coordinator = new ProductionVpnCoordinator(successful);
            Check(coordinator.Connect() == "CONNECTED_VERIFIED");
            Check(coordinator.Connect() == "ALREADY_CONNECTED");
            Check(successful.Secret is not null && successful.Secret.All(b => b == 0));
            Check(coordinator.ExplicitDisconnect() == "DISCONNECTED_VERIFIED");
            Check(successful.Calls.IndexOf("Stop") < successful.Calls.IndexOf("Release"));
            Check(successful.Calls.IndexOf("OffDurable") < successful.Calls.IndexOf("Release"));
            Check(!successful.Calls.Contains("Reprotect"));
            Check(coordinator.State == ProductionTunnelState.UnknownFailClosed);
            // The proof is negative by default, including 92-byte handshake-only
            // traffic, unchanged counter snapshots and mismatched challenges.
            var baseline = new AuthenticatedTunnelProof(true, true, true, true,
                true, true, true, 100, 200, 300, 400, 1, 1);
            Check(baseline.Verified);
            Check(!default(AuthenticatedTunnelProof).Verified);
            Check(!(baseline with { EchoRepliesMatched = 0 }).Verified);
            Check(!(baseline with { EchoRepliesMatched = 2 }).Verified);
            Check(!(baseline with { EchoRequestsSent = 0 }).Verified);
            Check(!(baseline with { SingleUseProbeNonceMatched = false }).Verified);
            Check(!(baseline with { ProbeSocketBoundToOwnedTunnel = false }).Verified);
            Check(!(baseline with { DnsProtectedBySystemWfp = false }).Verified);
            Check(!(baseline with { FixedSignedPeerConfirmed = false }).Verified);
            Check(!(baseline with { FreshAuthenticatedHandshake = false }).Verified);
            Check(!(baseline with { EncryptedRxAfter = 300 }).Verified);
            Check(!(baseline with { EncryptedTxAfter = 100 }).Verified);
            Check(!(baseline with { EncryptedRxBefore = -1 }).Verified);
            Check(!(baseline with { OwnedRoutesVerified = false }).Verified);
            Check(!(baseline with { NativeServiceRunning = false }).Verified);
            Check(assertions >= 80);
            Console.WriteLine("R27_PRODUCTION_TRANSITION_CONTRACT_PASS: " + assertions +
                " offline safety assertions; no real OS mutation or production permission");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R27_PRODUCTION_TRANSITION_CONTRACT_FAIL: " +
                ex.GetType().Name + " assertion=" + assertions);
            return false;
        }
    }
}
