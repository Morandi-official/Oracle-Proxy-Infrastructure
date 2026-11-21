"""R109 negative dual-epoch EVTX attestation tests, no guest/OS launch."""
import unittest
from datetime import datetime, timedelta, timezone

from windows_boot_evtx_witness import BootRecord, judge


T0 = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
KERNEL = "Microsoft-Windows-Kernel-General"
EVENTLOG = "EventLog"


def entry(seq, provider, event, seconds):
    return BootRecord(seq, event, provider, T0 + timedelta(seconds=seconds))


class SecondDiskBootWitness(unittest.TestCase):
    def setUp(self):
        self.before = [entry(10, KERNEL, 12, 120),
                       entry(11, EVENTLOG, 6005, 200)]
        self.after = list(self.before) + [
            entry(90, KERNEL, 12, 540), entry(91, EVENTLOG, 6005, 585)]
        self.start = T0 + timedelta(seconds=500)
        self.end = T0 + timedelta(seconds=1000)

    def assess(self, events, digest="second"):
        return judge("first", self.before, digest, events,
                     self.start, self.end)

    def test_fresh_second_boot_pair_passes_only_source_witness(self):
        verdict = self.assess(self.after)
        self.assertEqual(verdict.code,
                         "R99_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_WITNESSED")
        report = verdict.to_public_report()
        self.assertIn('"ga_or_production_authorized": false', report)
        self.assertIn('"wireguardnt_or_wfp_test_verified": false', report)
        self.assertIn('"guest_initiated_reboot_verified": false', report)

    def test_stale_digest_rejected_even_with_good_xml(self):
        self.assertEqual(self.assess(self.after, "first").code,
                         "R99_WINDOWS_SYSTEM_LOG_UNCHANGED_DENY")

    def test_no_new_kernel_is_denied(self):
        self.assertIn("DENY", self.assess(self.before + [
            entry(91, EVENTLOG, 6005, 585)]).code)

    def test_preexisting_record_identifiers_cannot_authenticate(self):
        self.assertIn("DENY", self.assess(self.before + [
            entry(9, KERNEL, 12, 550), entry(10, EVENTLOG, 6005, 590)]).code)

    def test_guest_future_clock_not_silently_adjusted(self):
        self.assertIn("DENY", self.assess(self.before + [
            entry(90, KERNEL, 12, 4200), entry(91, EVENTLOG, 6005, 4260)]).code)

    def test_reversed_order_not_accepted(self):
        self.assertIn("DENY", self.assess(self.before + [
            entry(90, KERNEL, 12, 620), entry(91, EVENTLOG, 6005, 540)]).code)


if __name__ == "__main__":
    unittest.main()
