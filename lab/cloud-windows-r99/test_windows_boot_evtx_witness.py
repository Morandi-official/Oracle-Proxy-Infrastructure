"""R99 independent Windows boot evidence adjudicator — deterministic negative tests."""
from datetime import datetime, timezone, timedelta
import unittest

from windows_boot_evtx_witness import (
    BootRecord, judge, parse_event_xml
)
def at(minute=0):
    return datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)

def row(record_id, event_id, provider, minute):
    return BootRecord(record_id, event_id, provider, at(minute))

def xml(provider, event_id, record_id=42, tm="2026-10-18T08:01:00.0000000Z"):
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="' + provider + '"/>'
        '<EventID>' + str(event_id) + '</EventID>'
        '<EventRecordID>' + str(record_id) + '</EventRecordID>'
        '<TimeCreated SystemTime="' + tm + '"/></System></Event>'
    )

class R99HostBootWitnessTests(unittest.TestCase):
    def setUp(self):
        self.before = [row(10,12,"Microsoft-Windows-Kernel-General",-6)]
        self.new = [row(11,12,"Microsoft-Windows-Kernel-General",1),
                    row(12,6005,"EventLog",2)]
    def judge(self, after=None, before=None, old_digest="old", new_digest="new",
              start=None,end=None):
        return judge(old_digest,
            self.before if before is None else before,
            new_digest,self.new if after is None else after,
            at(0) if start is None else start,
            at(4) if end is None else end)
    def test_real_fresh_both_sources_is_only_kernel_boot_witness(self):
        v=self.judge()
        self.assertEqual(v.code,"R99_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_WITNESSED")
        self.assertIn('"guest_initiated_reboot_verified": false',v.to_public_report())
        self.assertIn('"ga_or_production_authorized": false',v.to_public_report())
    def test_source_names_are_exact(self):
        self.assertIsNone(parse_event_xml(xml("attacker",12)))
        self.assertIsNone(parse_event_xml(xml("EventLog",12)))
        self.assertEqual(parse_event_xml(xml("Microsoft-Windows-Kernel-General",12)).record_id,42)
    def test_stale_preloaded_records_are_refused(self):
        other=[row(3,12,"Microsoft-Windows-Kernel-General",1),
               row(4,6005,"EventLog",2)]
        self.assertIn("DENY",self.judge(after=other).code)
    def test_empty_or_same_snapshot_has_no_boot_evidence(self):
        self.assertIn("DENY",self.judge(after=[]).code)
        self.assertEqual(self.judge(new_digest="old").code,
                         "R99_WINDOWS_SYSTEM_LOG_UNCHANGED_DENY")
    def test_kernel_only_or_eventlog_only_refused(self):
        for only in (self.new[:1],self.new[1:]):
            self.assertIn("DENY",self.judge(after=only).code)
    def test_wrong_provider_or_wrong_order_fails(self):
        bad=[row(11,6005,"EventLog",1),
             row(12,12,"Microsoft-Windows-Kernel-General",2)]
        self.assertIn("DENY",self.judge(after=bad).code)
    def test_old_events_even_with_higher_ids_refused(self):
        stale=[row(11,12,"Microsoft-Windows-Kernel-General",-20),
               row(12,6005,"EventLog",-19)]
        self.assertIn("DENY",self.judge(after=stale).code)
    def test_out_of_window_or_invalid_host_window_refused(self):
        self.assertIn("DENY",self.judge(start=at(5),end=at(6)).code)
        self.assertIn("DENY",self.judge(start=at(3),end=at(2)).code)
        self.assertIn("DENY",self.judge(end=at(30)).code)
    def test_malformed_xml_timezone_and_identifier_refused(self):
        for text in (
           "<Event>", xml("Microsoft-Windows-Kernel-General",12,record_id=0),
           xml("Microsoft-Windows-Kernel-General",12,tm="2026-10-18T08:01:00"),
           xml("Microsoft-Windows-Kernel-General",11),
           xml("Microsoft-Windows-Kernel-General",12,tm="not-a-time")
        ):
            self.assertIsNone(parse_event_xml(text))
    def test_reboot_is_not_inferred_from_single_kernel_start(self):
        v=self.judge()
        self.assertFalse("reboot_verified\": true" in v.to_public_report())

if __name__ == "__main__":
    unittest.main()
