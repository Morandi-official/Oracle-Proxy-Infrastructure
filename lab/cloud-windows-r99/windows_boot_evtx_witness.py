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
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RECORDS = 50000
MAX_WINDOW_SECONDS = 20 * 60


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
        timestamp = tc.attrib.get("SystemTime", "")
        if not timestamp.endswith("Z"):
            return None
        # Windows timestamp may carry 7 decimal places. datetime supports 6.
        utc = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if utc.tzinfo is None:
            return None
        return BootRecord(record_id, event_id, provider, utc.astimezone(timezone.utc))
    except (ValueError, TypeError, ET.ParseError, OverflowError):
        return None


def records_from_evtx(path: Path) -> tuple[str, list[BootRecord]]:
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
    with Evtx(str(path)) as log:
        for item in log.records():
            count += 1
            if count > MAX_RECORDS:
                raise ValueError("unbounded guest EVTX records")
            parsed = parse_event_xml(item.xml())
            if parsed:
                events.append(parsed)
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
        after_hash, after_events = records_from_evtx(args.after)
        report = judge(earlier_hash, earlier_events, after_hash, after_events,
                       _utc(args.start_utc), _utc(args.end_utc))
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
