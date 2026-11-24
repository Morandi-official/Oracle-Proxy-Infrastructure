"""Read-only Tailscale exit and physical NIC measurements."""

import json
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
EXIT_INTERFACE = "tailscale0"
DEVICES = {"enp0s6", EXIT_INTERFACE}
WINDOW_SECONDS = 5
LOAD_WAIT_SECONDS = 240
LOAD_CAPTURE_SECONDS = 15
LOAD_THRESHOLD_BYTES_S = 1024 * 1024
TAILSCALE = "/usr/local/libexec/oracle-proxy-tailnet/tailscale"
SOCKET = "/run/oracle-proxy-tailnet-exit/tailscaled.sock"
RATE_TABLE = "oracle_proxy_tailscale_rates"
FEATURES = (
    "generic-receive-offload", "generic-segmentation-offload", "rx-gro-list",
    "rx-udp-gro-forwarding", "tx-udp-segmentation", "large-receive-offload",
)
NIC_COUNTERS = (
    "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped",
    "rx_errors", "tx_errors", "rx_missed_errors", "rx_fifo_errors",
)


def read_command(*arguments):
    try:
        result = subprocess.run(arguments, check=True, capture_output=True, timeout=4, text=True)
        return result.stdout if len(result.stdout) <= 262144 else None
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return None


def json_command(*arguments):
    value = read_command(*arguments)
    try:
        return json.loads(value) if value is not None else None
    except ValueError:
        return None


def read_number(path):
    try:
        text = path.read_text().strip()
        return int(text) if text.isdecimal() else None
    except (OSError, ValueError):
        return None


def route_interface(family, destination):
    routes = json_command("ip", "-j", family, "route", "get", destination)
    if isinstance(routes, list) and len(routes) == 1 and isinstance(routes[0], dict):
        device = routes[0].get("dev")
        return device if device in DEVICES else None
    return None


def features_for(device):
    result = read_command("ethtool", "-k", device)
    if result is None:
        return {"status": "UNAVAILABLE"}
    found = {}
    for line in result.splitlines():
        match = re.fullmatch(r"\s*([a-z0-9-]+):\s+(on|off)(?:\s+(\[fixed\]))?\s*", line)
        if match and match[1] in FEATURES:
            found[match[1]] = {"on": match[2] == "on", "fixed": bool(match[3])}
    return {"status": "OBSERVED", "features": found}


def nic(device):
    path = Path("/sys/class/net") / device
    link = json_command("ip", "-j", "-d", "link", "show", "dev", device)
    flags = link[0] if isinstance(link, list) and len(link) == 1 and isinstance(link[0], dict) else {}
    queues = path / "queues"
    return {
        "mtu": read_number(path / "mtu"),
        "rx_queues": len(list(queues.glob("rx-*"))),
        "tx_queues": len(list(queues.glob("tx-*"))),
        "software_limits": {name: flags[name] for name in ("gso_max_size", "gso_max_segs", "gro_max_size")
                            if type(flags.get(name)) is int and flags[name] >= 0},
        "offloads": features_for(device),
    }


def nic_counters(device):
    path = Path("/sys/class/net") / device / "statistics"
    return {metric: count for metric in NIC_COUNTERS if (count := read_number(path / metric)) is not None}


def udp_counters():
    wanted = {"InDatagrams", "OutDatagrams", "InErrors", "RcvbufErrors", "SndbufErrors", "InCsumErrors"}
    columns = [line.split()[1:] for line in Path("/proc/net/snmp").read_text().splitlines() if line.startswith("Udp:")]
    if len(columns) != 2 or len(columns[0]) != len(columns[1]):
        return {}
    return {name: int(value) for name, value in zip(*columns) if name in wanted and value.isdecimal()}


def queues(device):
    result = json_command("tc", "-j", "-s", "qdisc", "show", "dev", device)
    if not isinstance(result, list):
        return []
    rows = []
    for item in result[:64]:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        if not isinstance(kind, str) or not re.fullmatch(r"[a-z0-9_]{1,24}", kind):
            continue
        numbers = {name: item[name] for name in ("drops", "overlimits", "requeues", "backlog", "qlen")
                   if type(item.get(name)) is int and item[name] >= 0}
        # qdisc handles and classifiers stay internal. Report one summary per queue.
        rows.append({"kind": kind, "root": item.get("root") is True, **numbers})
    return rows


def cpu_ticks():
    rows = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()[:9]
        if len(fields) != 9 or not re.fullmatch(r"cpu[0-9]*", fields[0]) or not all(v.isdecimal() for v in fields[1:]):
            continue
        rows[fields[0]] = tuple(map(int, fields[1:]))
    return rows


def cpu_usage(before, after, *, include_cores=False):
    percentages = {}
    cores = {}
    for name, old in before.items():
        if name not in after:
            continue
        changes = tuple(end - start for start, end in zip(old, after[name]))
        total = sum(changes)
        if total <= 0 or any(value < 0 for value in changes):
            continue
        percentages[name] = round(100 * (total - changes[3] - changes[4]) / total, 1)
        if name != "cpu":
            cores[name] = {"busy_pct": percentages[name], "softirq_pct": round(100 * changes[6] / total, 1)}
    summary = {"host_busy_pct": percentages.get("cpu"),
               "busiest_core_pct": max((core["busy_pct"] for core in cores.values()), default=None),
               "peak_core_softirq_pct": max((core["softirq_pct"] for core in cores.values()), default=None)}
    if include_cores:
        summary["per_core"] = cores
    return summary


def peer_paths():
    value = json_command(TAILSCALE, "--socket=" + SOCKET, "status", "--json")
    if not isinstance(value, dict) or value.get("BackendState") != "Running":
        return {"exit_running": False}
    peers = value.get("Peer") or {}
    if not isinstance(peers, dict):
        return {"exit_running": True, "status": "PEERS_UNAVAILABLE"}
    active = [row for row in peers.values() if isinstance(row, dict) and row.get("Active") is True]
    direct = sum(bool(row.get("CurAddr")) for row in active)
    relayed = sum(bool(row.get("Relay")) and not row.get("CurAddr") for row in active)
    return {"exit_running": True, "active_direct_count": direct, "active_relay_count": relayed}


def rate_buckets():
    result = json_command("/usr/sbin/nft", "--json", "list", "table", "inet", RATE_TABLE)
    if not isinstance(result, dict) or not isinstance(result.get("nftables"), list):
        tables = json_command("/usr/sbin/nft", "--json", "list", "tables")
        if isinstance(tables, dict) and isinstance(rows := tables.get("nftables"), list):
            present = any(isinstance(row, dict) and isinstance(table := row.get("table"), dict)
                          and table.get("name") == RATE_TABLE and table.get("family") == "inet" for row in rows)
            if not present:
                return {"status": "OBSERVED", "download_buckets": 0, "upload_buckets": 0}
        return {"status": "UNAVAILABLE"}
    names = {limit["name"] for item in result["nftables"] if isinstance(item, dict)
             and isinstance(limit := item.get("limit"), dict) and limit.get("table") == RATE_TABLE
             and isinstance(limit.get("name"), str)}
    return {"status": "OBSERVED", "download_buckets": sum(name.startswith("daddr_") for name in names),
            "upload_buckets": sum(name.startswith("saddr_") for name in names)}


def delta(before, after):
    return {name: value - before[name] for name, value in after.items() if name in before and value >= before[name]}


def physical_interface():
    config = json.loads((REPO / "ops/network/endpoints.json").read_bytes())
    device = config.get("interface")
    if device != "enp0s6":
        raise ValueError("TAILNET_PERF_PHYSICAL_INTERFACE_UNVERIFIED")
    v4 = route_interface("-4", "1.1.1.1")
    v6 = route_interface("-6", "2606:4700:4700::1111")
    if (v4, v6) != (device, device):
        raise ValueError("TAILNET_PERF_PHYSICAL_ROUTE_UNVERIFIED")
    return device


def observe():
    device = physical_interface()
    kernel = re.match(r"(\d{1,3})\.(\d{1,3})\.(\d{1,5})", platform.release())
    version = tuple(map(int, kernel.groups())) if kernel else ()
    before = {port: nic_counters(port) for port in (device, EXIT_INTERFACE)}
    udp_before = udp_counters()
    cpu_before = cpu_ticks()
    started = time.monotonic()
    time.sleep(WINDOW_SECONDS)
    after = {port: nic_counters(port) for port in before}
    elapsed = round(time.monotonic() - started, 3)
    udp_after = udp_counters()
    cpu_after = cpu_ticks()
    return {
        "status": "OBSERVED",
        "sample_seconds": elapsed,
        "kernel": ".".join(map(str, version)),
        "kernel_supports_upstream_udp_gro": version >= (6, 2),
        "paths": peer_paths(),
        "rate_policy": rate_buckets(),
        "physical": nic(device),
        "tunnel": nic(EXIT_INTERFACE),
        "physical_queues": queues(device),
        "network_counter_deltas": {port: delta(before[port], after[port]) for port in before},
        "udp_counter_deltas": delta(udp_before, udp_after),
        "cpu": cpu_usage(cpu_before, cpu_after),
    }


def utc_time():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def load_snapshot(device):
    roots = [queue for queue in queues(device) if queue["root"]]
    return {
        "time": time.monotonic(), "utc": utc_time(),
        "interfaces": {port: nic_counters(port) for port in (device, EXIT_INTERFACE)},
        "udp": udp_counters(), "cpu": cpu_ticks(), "queue": roots[0] if len(roots) == 1 else None,
    }


def load_interval(before, after):
    elapsed = max(after["time"] - before["time"], .001)
    interfaces = {device: delta(old, after["interfaces"][device])
                  for device, old in before["interfaces"].items()}
    tunnel = interfaces[EXIT_INTERFACE]
    directions = {key: round(tunnel.get(key, 0) / elapsed) for key in ("rx_bytes", "tx_bytes")}
    old_queue, new_queue = before["queue"], after["queue"]
    queue = {"status": "UNAVAILABLE_OR_CHANGED"}
    if old_queue is not None and new_queue is not None and old_queue["kind"] == new_queue["kind"]:
        counters = {key: new_queue[key] for key in ("drops", "overlimits", "requeues") if key in new_queue}
        queue = {"kind": new_queue["kind"], "deltas": delta(old_queue, counters),
                 "backlog_bytes_end": new_queue.get("backlog"), "queue_length_end": new_queue.get("qlen")}
    return {
        "started_at": before["utc"], "ended_at": after["utc"], "seconds": round(elapsed, 3),
        "tunnel_rx_bytes_s": directions["rx_bytes"], "tunnel_tx_bytes_s": directions["tx_bytes"],
        "network_counter_deltas": interfaces, "udp_counter_deltas": delta(before["udp"], after["udp"]),
        "cpu": cpu_usage(before["cpu"], after["cpu"], include_cores=True), "physical_queue": queue,
    }


def observe_load():
    device = physical_interface()
    started_at = utc_time()
    started = time.monotonic()
    deadline = started + LOAD_WAIT_SECONDS
    old = load_snapshot(device)
    first = peak_rx = peak_tx = rate_at_first = None
    hits = intervals = readable = 0
    while (remaining := deadline - time.monotonic()) > 0:
        time.sleep(min(remaining, 1))
        new = load_snapshot(device)
        interval = load_interval(old, new)
        intervals += 1
        old = new
        if {"rx_bytes", "tx_bytes"} <= interval["network_counter_deltas"][EXIT_INTERFACE].keys():
            readable += 1
        else:
            continue
        if max(interval["tunnel_rx_bytes_s"], interval["tunnel_tx_bytes_s"]) < LOAD_THRESHOLD_BYTES_S:
            continue
        hits += 1
        if first is None:
            first = peak_rx = peak_tx = interval
            deadline = min(deadline, new["time"] + LOAD_CAPTURE_SECONDS)
            rate_at_first = rate_buckets()
        if interval["tunnel_rx_bytes_s"] > peak_rx["tunnel_rx_bytes_s"]:
            peak_rx = interval
        if interval["tunnel_tx_bytes_s"] > peak_tx["tunnel_tx_bytes_s"]:
            peak_tx = interval
    status = "LOAD_OBSERVED" if hits else "LOAD_WAIT_TIMEOUT" if readable else "TUNNEL_COUNTERS_UNAVAILABLE"
    report = {"status": status, "started_at": started_at,
              "ended_at": utc_time(), "elapsed_seconds": round(time.monotonic() - started, 3),
              "threshold_bytes_s": LOAD_THRESHOLD_BYTES_S, "checked_intervals": intervals,
              "readable_tunnel_intervals": readable, "qualifying_intervals": hits}
    if hits:
        report["first_load"] = first
        report["peak_rx"] = peak_rx
        report["peak_tx"] = peak_tx
        report["rate_policy_at_first_load"] = rate_at_first
        report["rate_policy_at_end"] = rate_buckets()
    return report


if __name__ == "__main__":
    try:
        modes = {(): observe, ("--during-load",): observe_load}
        if (mode := modes.get(tuple(sys.argv[1:]))) is None:
            raise ValueError("TAILNET_PERF_UNKNOWN_MODE")
        print(json.dumps(mode(), sort_keys=True))
    except (OSError, ValueError, TypeError) as error:
        category = str(error)
        if category not in ("TAILNET_PERF_PHYSICAL_INTERFACE_UNVERIFIED", "TAILNET_PERF_PHYSICAL_ROUTE_UNVERIFIED"):
            category = "TAILNET_PERFORMANCE_OBSERVATION_UNAVAILABLE"
        print(json.dumps({"status": "UNAVAILABLE", "reason": category}))
