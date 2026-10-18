"""R99 independent Windows boot evidence adjudicator — deterministic negative tests."""
from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import patch
from tempfile import TemporaryDirectory
from pathlib import Path
import sys
import types

from windows_boot_evtx_witness import (
    BootRecord, judge, parse_event_xml, summarize_safe_boot_counters, records_from_evtx, event_systemtime_utc, classify_clock_offset
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
    def test_future_guest_clock_is_diagnostic_never_approval(self):
        for minutes, code in ((4,"within"),(8,"after_40s_5m"),
                              (50,"after_5m_1h"),
                              (9*60,"after_1h_day"),
                              (60*48,"after_gt_day")):
            self.assertEqual(classify_clock_offset(at(minutes),at(0),at(4)),code)
        future = [row(11,12,"Microsoft-Windows-Kernel-General",9*60),
                  row(12,6005,"EventLog",9*60+2)]
        denied=self.judge(after=future)
        self.assertIn("DENY",denied.code)
        self.assertFalse('"genuine_windows_kernel_boot_verified": true'
                         in denied.to_public_report())
        self.assertEqual(classify_clock_offset(None,at(0),at(4)),"unreadable")

    def test_windows_python_evtx_naive_systemtime_is_utc_not_local_time(self):
        # Debian/Ubuntu python-evtx calls datetime.isoformat(' '), and
        # Windows SystemTime is UTC without an explicit zone in that output.
        raw = "2026-10-18 08:01:00.000000"
        stamp = event_systemtime_utc(raw)
        self.assertEqual(stamp, at(1))
        self.assertEqual(parse_event_xml(xml(
            "Microsoft-Windows-Kernel-General", 12, tm=raw)).utc, at(1))
        self.assertEqual(parse_event_xml(xml(
            "EventLog", 6005, tm="2026-10-18 08:02:00")).utc, at(2))
        self.assertEqual(event_systemtime_utc(
            "2026-10-18T08:01:00.0000000Z"), at(1))
        self.assertIsNone(event_systemtime_utc(
            "2026-10-18T08:01:00+09:00"))
        self.assertIsNone(event_systemtime_utc(
            "10/18/2026 08:01:00"))
        self.assertIsNone(event_systemtime_utc(""))

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
           xml("Microsoft-Windows-Kernel-General",12,tm="10/18/2026 08:01:00"),
           xml("Microsoft-Windows-Kernel-General",12,tm="2026-10-18T08:01:00+09:00"),
           xml("Microsoft-Windows-Kernel-General",11),
           xml("Microsoft-Windows-Kernel-General",12,tm="not-a-time")
        ):
            self.assertIsNone(parse_event_xml(text))
    def test_diagnostics_distinguish_stale_from_live_events_without_records(self):
        old = [row(1, 12, "Microsoft-Windows-Kernel-General", -20),
               row(2, 6005, "EventLog", -19)]
        counters = summarize_safe_boot_counters(self.before, old, at(0), at(4))
        self.assertEqual(counters["r99_kernel12_any_date"], 1)
        self.assertEqual(counters["r99_eventlog6005_any_date"], 1)
        self.assertEqual(counters["r99_kernel12_in_host_window"], 0)
        self.assertEqual(counters["r99_eventlog6005_in_host_window"], 0)
        self.assertEqual(counters["r99_kernel12_older_than_host_window"], 1)
        self.assertEqual(counters["r99_eventlog6005_older_than_host_window"], 1)
        self.assertFalse(any("record_id" in key or "host_start" in key
                             for key in counters.keys()))

    def test_synthetic_non_boot_windows_events_only_report_bounded_counters(self):
        # Fake EVTX parser yields only controlled XML data: no real Windows
        # guest log, no PII and no external resource touched in this test.
        sample = [
            xml("Microsoft-Windows-Setup", 1, 1, "2026-10-18T07:00:00.0000000Z"),
            xml("Microsoft-Windows-Kernel-PnP", 2, 2, "2026-10-18T08:01:00.0000000Z"),
            xml("EventLog", 3, 3, "2026-10-18T08:20:00.0000000Z"),
        ]
        class Record:
            def __init__(self, body): self.body = body
            def xml(self): return self.body
        class FakeEvtx:
            def __init__(self, _): pass
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def records(self):
                return iter(Record(data) for data in sample)
        package = types.ModuleType("Evtx")
        submodule = types.ModuleType("Evtx.Evtx")
        submodule.Evtx = FakeEvtx
        with TemporaryDirectory() as td:
            filename = Path(td) / "synthetic.evtx"
            filename.write_bytes(b"ElfFile\x00" + b"\x00" * 4096)
            with patch.dict(sys.modules, {"Evtx": package, "Evtx.Evtx": submodule}):
                counters = {}
                _, matched = records_from_evtx(
                    filename, scan=counters, host_start=at(0), host_end=at(4))
            self.assertEqual(len(matched), 0)
            self.assertEqual(counters["r99_evtx_total_records"], 3)
            self.assertEqual(counters["r99_system_events_before_host_window"], 1)
            self.assertEqual(counters["r99_system_events_within_host_window"], 1)
            self.assertEqual(counters["r99_system_events_after_host_window"], 1)
            self.assertEqual(counters["r99_allowlisted_microsoft_boot_source_0_count"], 1)
            self.assertEqual(counters["r99_allowlisted_microsoft_boot_source_3_count"], 1)
            self.assertFalse(any("provider_name" in k or "record_id" in k
                                 for k in counters))

    def test_reboot_is_not_inferred_from_single_kernel_start(self):
        v=self.judge()
        self.assertFalse("reboot_verified\": true" in v.to_public_report())

if __name__ == "__main__":
    unittest.main()
