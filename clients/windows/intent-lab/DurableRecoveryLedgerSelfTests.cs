namespace OracleProxy.IntentLab;
internal static class DurableRecoveryLedgerSelfTests
{
    internal static bool Run()
    {
        string root = Path.Combine(Environment.GetEnvironmentVariable("RUNNER_TEMP")!,
            "oracle-r32-" + Guid.NewGuid().ToString("N"));
        int checks=0;
        void Check(bool ok) { if (!ok) throw new InvalidOperationException("R32 check "+checks); checks++; }
        void Reject(Action f) {try {f();}catch(InvalidOperationException){checks++;return;} throw new InvalidOperationException("Unsafe journal mutation");}
        Directory.CreateDirectory(root);
        try {
            Reject(() => new DurableRecoveryLedger(root));
            DurableRecoveryLedger.ProtectFreshTestFolder(root);
            var ledger = new DurableRecoveryLedger(root);
            var initial = ledger.Read();
            Check(initial.Phase == RecoveryPhase.UnknownFailClosed);
            Check(initial.RequiresExternalWfpAudit && !initial.MayAutomaticallyReleaseWfp);
            Guid id=Guid.NewGuid();
            var phases=new [] {
                RecoveryPhase.ConnectPrepared,RecoveryPhase.ProtectedConnected,
                RecoveryPhase.DisconnectPrepared,RecoveryPhase.GuardReleasePending,
                RecoveryPhase.OffRecordedNeedsOsAudit
            };
            var previous=RecoveryPhase.UnknownFailClosed;
            foreach (var phase in phases) {
                var saved=ledger.Advance(previous,phase,id);
                Check(saved.Revision>=1);
                Check(saved.Phase==phase && saved.TransactionId==id);
                var afterCrash=new DurableRecoveryLedger(root).Read();
                Check(afterCrash.Phase==phase && afterCrash.RequiresExternalWfpAudit);
                Check(!afterCrash.MayAutomaticallyReleaseWfp);
                Reject(()=>ledger.Advance(previous,phase,id));
                previous=phase;
            }
            Reject(()=>ledger.Advance(previous,RecoveryPhase.ConnectPrepared,id));
            Reject(()=>ledger.Advance(previous,RecoveryPhase.OffRecordedNeedsOsAudit,Guid.NewGuid()));
            string file=Path.Combine(root,"transition-ledger.dpapi");
            var bytes=File.ReadAllBytes(file);
            Check(bytes.Length>32 && !System.Text.Encoding.UTF8.GetString(bytes).Contains("OffRecordedNeedsOsAudit"));
            bytes[bytes.Length/2]^=0x32;
            File.WriteAllBytes(file,bytes);
            Check(new DurableRecoveryLedger(root).Read().Phase==RecoveryPhase.Quarantined);
            Reject(()=>ledger.Advance(RecoveryPhase.UnknownFailClosed,RecoveryPhase.ConnectPrepared,id));
            File.Delete(file);
            Check(new DurableRecoveryLedger(root).Read().Phase==RecoveryPhase.UnknownFailClosed);
            Check(checks>=28);
            Console.WriteLine("R32_DURABLE_CRASH_RECOVERY_PASS: "+checks+
                " real Windows DPAPI journal/restart/tamper assertions; no WFP/SCM mutation");
            return true;
        } catch(Exception e) {Console.Error.WriteLine("R32_DURABLE_CRASH_RECOVERY_FAIL: "+e.GetType().Name+" check="+checks);return false;}
        finally {try{Directory.Delete(root,true);}catch{}}
    }
}
