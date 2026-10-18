"""R99 independent host/offline EVTX Windows kernel boot witness.

No guest agent injection, Windows script execution, network, driver or WFP
mutation. Uses preexisting Windows event logs read ONLY after guest stop.
Everything is adversarial/untrusted until validated; do not dump XML, addresses
or identifying event fields into CI logs.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
import argparse
import json
import re
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# python-evtx 0.7.4 renders the binary SYSTEMTIME with datetime.isoformat(' '),
# which yields an offset-naive string such as "2026-10-18 09:10:11.123456".
# Windows TimeCreated.SystemTime is defined as system event UTC time. Interpret
# ONLY this exact binary-SYSTEMTIME serialization as UTC. Never infer the
# host's local timezone or accept ambiguous locale timestamps.
NAIVE_EVTX_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?$"
)


def event_systemtime_utc(raw: str) -> datetime | None:
    if not isinstance(raw, str) or not 19 <= len(raw) <= 40:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if value.tzinfo is None:
            if not NAIVE_EVTX_UTC.fullmatch(raw):
                return None
            value = value.replace(tzinfo=timezone.utc)
        # Windows event SystemTime is always UTC, including when python-evtx
        # serializes its raw binary SYSTEMTIME without a timezone suffix.
        if value.utcoffset() != timedelta(0):
            return None
        return value.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RECORDS = 50000
MAX_WINDOW_SECONDS = 20 * 60
# Fixed Microsoft Windows boot/setup sources only. Never emit arbitrary
# providers, event messages, payloads, record IDs or exact times.
DIAGNOSTIC_PROVIDERS = (
    "Microsoft-Windows-Setup",
    "Microsoft-Windows-Kernel-Boot",
    "Microsoft-Windows-Kernel-General",
    "Microsoft-Windows-Kernel-PnP",
    "Microsoft-Windows-Winlogon",
    "Microsoft-Windows-Eventlog",
    "EventLog",
)

# Coarse bins only: event times, exact offsets, host clock details and
# record payloads must NEVER appear in GitHub logs. A bin is for diagnosis,
# not authorization. All non-host-window records STILL FAIL the boot gate.
CLOCK_BINS = ("before_gt_day", "before_1h_day", "before_5m_1h",
              "before_40s_5m", "within", "after_40s_5m",
              "after_5m_1h", "after_1h_day", "after_gt_day")


def classify_clock_offset(stamp: datetime | None, start: datetime,
                          end: datetime) -> str:
    if stamp is None or stamp.tzinfo is None or start.tzinfo is None or end.tzinfo is None:
        return "unreadable"
    lower = start - timedelta(seconds=40)
    upper = end + timedelta(seconds=40)
    if lower <= stamp <= upper:
        return "within"
    if stamp < lower:
        delay = (start - stamp).total_seconds()
        if delay > 86400: return "before_gt_day"
        if delay > 3600: return "before_1h_day"
        if delay > 300: return "before_5m_1h"
        return "before_40s_5m"
    delay = (stamp - end).total_seconds()
    if delay > 86400: return "after_gt_day"
    if delay > 3600: return "after_1h_day"
    if delay > 300: return "after_5m_1h"
    return "after_40s_5m"




@dataclass(frozen=True)
class BootRecord:
    record_id: int
    event_id: int
    provider: str
    utc: datetime


@dataclass(frozen=True)
class BootVerdict:
    code: str
    fresh_kernel_starts: int
    fresh_eventlog_starts: int
    def to_public_report(self) -> str:
        return json.dumps({
            "code": self.code,
            "fresh_kernel_starts": self.fresh_kernel_starts,
            "fresh_eventlog_starts": self.fresh_eventlog_starts,
            "genuine_windows_kernel_boot_verified": self.code == "R99_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_WITNESSED",
            "guest_initiated_reboot_verified": False,
            "wireguardnt_or_wfp_test_verified": False,
            "ga_or_production_authorized": False,
        }, sort_keys=True)


def parse_event_xml(value: str) -> BootRecord | None:
    try:
        root = ET.fromstring(value)
        if root.tag != NS + "Event":
            return None
        sys = root.find(NS + "System")
        if sys is None:
            return None
        provider_node = sys.find(NS + "Provider")
        id_node = sys.find(NS + "EventID")
        seq = sys.find(NS + "EventRecordID")
        tc = sys.find(NS + "TimeCreated")
        if any(x is None for x in (provider_node, id_node, seq, tc)):
            return None
        provider = provider_node.attrib.get("Name", "")
        event_id = int(id_node.text or "-1")
        if (provider, event_id) not in (
            ("Microsoft-Windows-Kernel-General", 12),
            ("EventLog", 6005),
        ):
            return None
        record_id = int(seq.text or "0")
        if record_id <= 0:
            return None
        # SystemTime's UTC meaning survives the python-evtx output style:
        # it may have Z, an explicit +00:00 or the library's naive space-ISO
        # representation. No host-local offset inference is permitted.
        utc = event_systemtime_utc(tc.attrib.get("SystemTime", ""))
        if utc is None:
            return None
        return BootRecord(record_id, event_id, provider, utc)
    except (ValueError, TypeError, ET.ParseError, OverflowError):
        return None


def records_from_evtx(path: Path, *, scan: dict | None = None, host_start: datetime | None = None, host_end: datetime | None = None) -> tuple[str, list[BootRecord]]:
    if not path.is_file():
        raise ValueError("guest System.evtx not extracted")
    size = path.stat().st_size
    if size < 4096 or size > MAX_FILE_BYTES:
        raise ValueError("empty/oversize guest System.evtx")
    with path.open("rb") as f:
        if f.read(8) != b"ElfFile\x00":
            raise ValueError("not a genuine EVTX file header")
    from Evtx.Evtx import Evtx  # version + artifact hash independently pinned in CI
    events: list[BootRecord] = []
    count = 0
    xml_parseable = 0
    system_events_with_identity = 0
    provider_counts = {name: 0 for name in DIAGNOSTIC_PROVIDERS}
    event_timing = {"before": 0, "within": 0, "after": 0, "unreadable": 0}
    kernel_clock_bins = {key: 0 for key in CLOCK_BINS}
    header_clock_bins = {key: 0 for key in CLOCK_BINS}
    header_unavailable = 0
    event_header_disagreement_over_5m = 0
    with Evtx(str(path)) as log:
        for item in log.records():
            count += 1
            if count > MAX_RECORDS:
                raise ValueError("unbounded guest EVTX records")
            # Ordinary Windows system events (not only Kernel 12 / EventLog
            # 6005) are counted to distinguish a valid but uninitialized
            # System.evtx from an EVTX parser that sees zero real records.
            xml_value = item.xml()
            try:
                root = ET.fromstring(xml_value)
                xml_parseable += 1
                system = root.find(NS + "System")
                if system is not None and system.find(NS + "EventID") is not None and (
                        system.find(NS + "Provider") is not None):
                    system_events_with_identity += 1
                    provider_name = system.find(NS + "Provider").get("Name", "")
                    if provider_name in provider_counts:
                        provider_counts[provider_name] += 1
                    # This is an independent binary EVTX record-header
                    # FILETIME decoded by python-evtx. If the API returns an
                    # ambiguous/untyped time do not trust it as evidence.
                    if host_start is not None and host_end is not None:
                        header = None
                        header_fn = getattr(item, "timestamp", None)
                        if callable(header_fn):
                            try:
                                value = header_fn()
                                if isinstance(value, datetime) and value.tzinfo is not None:
                                    if value.utcoffset() == timedelta(0):
                                        header = value.astimezone(timezone.utc)
                            except (TypeError, ValueError, OverflowError):
                                pass
                        if header is None:
                            header_unavailable += 1
                        else:
                            hbin = classify_clock_offset(header, host_start, host_end)
                            if hbin in header_clock_bins:
                                header_clock_bins[hbin] += 1
                    # Only categorical time-window counters; do not expose
                    # raw XML, exact timestamps, source IPs, event payloads.
                    if host_start is not None and host_end is not None:
                        created = system.find(NS + "TimeCreated")
                        raw_time = created.get("SystemTime") if created is not None else ""
                        stamp = event_systemtime_utc(raw_time)
                        # Count ONLY Kernel-General event 12 / EventLog 6005
                        # in these coarse guest clock bins.
                        id_node = system.find(NS + "EventID")
                        try:
                            candidate_id = int(id_node.text or "-1")
                        except ValueError:
                            candidate_id = -1
                        if (provider_name, candidate_id) in (
                            ("Microsoft-Windows-Kernel-General", 12),
                            ("EventLog", 6005),
                        ):
                            bin_name = classify_clock_offset(stamp, host_start, host_end)
                            if bin_name in kernel_clock_bins:
                                kernel_clock_bins[bin_name] += 1
                            if stamp is not None and header is not None and (
                                    abs((stamp - header).total_seconds()) > 300):
                                event_header_disagreement_over_5m += 1
                        if stamp is None:
                            event_timing["unreadable"] += 1
                        elif stamp < host_start - timedelta(seconds=40):
                            event_timing["before"] += 1
                        elif stamp > host_end + timedelta(seconds=40):
                            event_timing["after"] += 1
                        else:
                            event_timing["within"] += 1
            except ET.ParseError:
                pass
            parsed = parse_event_xml(xml_value)
            if parsed:
                events.append(parsed)
    if scan is not None:
        scan.update({
            "r99_evtx_total_records": count,
            "r99_evtx_xml_parseable_records": xml_parseable,
            "r99_evtx_system_records_with_provider_id": system_events_with_identity,
            "r99_evtx_recognized_windows_boot_records": len(events),
            "r99_system_events_before_host_window": event_timing["before"],
            "r99_system_events_within_host_window": event_timing["within"],
            "r99_system_events_after_host_window": event_timing["after"],
            "r99_system_events_with_unreadable_clock": event_timing["unreadable"],
            "r99_raw_evtx_record_header_utc_unavailable": header_unavailable,
            "r99_boot_event_header_disagreements_gt5min": event_header_disagreement_over_5m,
        })
        for k in CLOCK_BINS:
            scan["r99_boot_event_clock_bin_" + k] = kernel_clock_bins[k]
            scan["r99_binary_evtx_header_clock_bin_" + k] = header_clock_bins[k]
        for i, name in enumerate(DIAGNOSTIC_PROVIDERS):
            scan["r99_allowlisted_microsoft_boot_source_" + str(i) + "_count"] = provider_counts[name]
    return sha256(path.read_bytes()).hexdigest(), events


def judge(
    before_digest: str | None,
    before: list[BootRecord],
    after_digest: str,
    after: list[BootRecord],
    host_start: datetime,
    host_end: datetime,
) -> BootVerdict:
    if (host_start.tzinfo is None or host_end.tzinfo is None or
        host_end <= host_start or
        (host_end - host_start).total_seconds() > MAX_WINDOW_SECONDS):
        return BootVerdict("R99_INVALID_INDEPENDENT_HOST_TIME_WINDOW_DENY", 0, 0)
    if before_digest is not None and before_digest == after_digest:
        return BootVerdict("R99_WINDOWS_SYSTEM_LOG_UNCHANGED_DENY", 0, 0)
    prev_id = max((r.record_id for r in before), default=0)
    # Small host clock slack tolerates VM RTC skew only, never accepts stale
    # preloaded VHD event records. All extracted records must postdate baseline.
    low = host_start.astimezone(timezone.utc) - timedelta(seconds=40)
    high = host_end.astimezone(timezone.utc) + timedelta(seconds=40)
    fresh = [
        x for x in after
        if x.record_id > prev_id and low <= x.utc <= high
    ]
    kernels = [
        x for x in fresh
        if (x.event_id == 12 and x.provider == "Microsoft-Windows-Kernel-General")
    ]
    services = [
        x for x in fresh if x.event_id == 6005 and x.provider == "EventLog"
    ]
    # Corroborating kernel and EventLog service records must occur in order.
    corroborated = any(
        0 <= (s.utc - k.utc).total_seconds() <= 240
        for k in kernels for s in services
    )
    if not corroborated:
        return BootVerdict("R99_FRESH_WINDOWS_KERNEL_BOOT_NOT_CORROBORATED_DENY",
                           len(kernels), len(services))
    return BootVerdict("R99_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_WITNESSED",
                       len(kernels), len(services))


def summarize_safe_boot_counters(
    before: list[BootRecord],
    after: list[BootRecord],
    host_start: datetime,
    host_end: datetime,
) -> dict[str, int]:
    # No guest XML, timestamps, addresses, file contents, record IDs or keys
    # leave this runner. Only numbers of recognized OS startup events.
    prior_max = max((e.record_id for e in before), default=0)
    lower = host_start.astimezone(timezone.utc) - timedelta(seconds=40)
    upper = host_end.astimezone(timezone.utc) + timedelta(seconds=40)
    kernels = [e for e in after if e.event_id == 12 and
               e.provider == "Microsoft-Windows-Kernel-General"]
    logs = [e for e in after if e.event_id == 6005 and e.provider == "EventLog"]
    def inside(e: BootRecord) -> bool:
        return e.record_id > prior_max and lower <= e.utc <= upper
    return {
        "r99_kernel12_any_date": len(kernels),
        "r99_eventlog6005_any_date": len(logs),
        "r99_kernel12_in_host_window": sum(inside(e) for e in kernels),
        "r99_eventlog6005_in_host_window": sum(inside(e) for e in logs),
        "r99_kernel12_older_than_host_window": sum(e.utc < lower for e in kernels),
        "r99_eventlog6005_older_than_host_window": sum(e.utc < lower for e in logs),
        "r99_kernel12_newer_than_host_window": sum(e.utc > upper for e in kernels),
        "r99_eventlog6005_newer_than_host_window": sum(e.utc > upper for e in logs),
    }


def _utc(value: str) -> datetime:
    d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if d.utcoffset() != timedelta(0):
        raise ValueError("only UTC timestamps allowed")
    return d


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--before", type=Path)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--start-utc", required=True)
    p.add_argument("--end-utc", required=True)
    args = p.parse_args()
    try:
        earlier_hash, earlier_events = (
            records_from_evtx(args.before) if args.before is not None and
            args.before.is_file() else (None, [])
        )
        counters: dict[str, int] = {}
        start = _utc(args.start_utc)
        end = _utc(args.end_utc)
        after_hash, after_events = records_from_evtx(
            args.after, scan=counters, host_start=start, host_end=end)
        print(json.dumps(counters, sort_keys=True))
        if end > start and (end - start).total_seconds() <= MAX_WINDOW_SECONDS:
            print(json.dumps(summarize_safe_boot_counters(
                earlier_events, after_events, start, end), sort_keys=True))
        report = judge(earlier_hash, earlier_events, after_hash, after_events,
                       start, end)
        print(report.to_public_report())
        return 0 if report.code == "R99_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_WITNESSED" else 2
    except Exception as exc:
        # No sensitive guest records or paths are ever printed.
        print(json.dumps({
            "code": "R99_OFFLINE_WINDOWS_BOOT_LOG_UNVERIFIABLE_DENY",
            "error_class": type(exc).__name__,
            "genuine_windows_kernel_boot_verified": False,
            "ga_or_production_authorized": False
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
