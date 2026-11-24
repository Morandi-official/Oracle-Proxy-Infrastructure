"""Bounded independent TCP benchmark against Clouvider's published London tools."""

import ipaddress
import json
import math
import os
import statistics
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic


HOST = "lon.speedtest.clouvider.net"
ORIGIN = "https://" + HOST + "/backend"
IPERF = Path("/usr/bin/iperf3")
PRLIMIT = Path("/usr/bin/prlimit")
IPERF_PORT = "5205"
IPERF_REQUEST_BYTES = 12 * 1024 * 1024
IPERF_SAMPLE_LIMIT = 16 * 1024 * 1024
HTTP_DOWNLOAD = 8 * 1024 * 1024
HTTP_UPLOAD = 4 * 1024 * 1024
STREAMS = 4
CLOUVIDER_URLS = (ORIGIN + "/garbage.php?ckSize=8", ORIGIN + "/empty.php")
CLOUDFLARE_URLS = ("https://speed.cloudflare.com/__down?bytes=" + str(HTTP_DOWNLOAD),
                   "https://speed.cloudflare.com/__up")


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def resolve(family, base):
    output = base.command("/usr/bin/getent", "ahostsv" + str(family), HOST, timeout=5)
    if output.returncode or len(output.stdout) > 16384:
        raise base.ProbeFailure("LONDON_ORIGIN_RESOLUTION_FAILED")
    for line in output.stdout.decode("ascii").splitlines():
        fields = line.split()
        if not fields:
            continue
        ip = ipaddress.ip_address(fields[0])
        if (ip.version == family and ip.is_global and getattr(ip, "ipv4_mapped", None) is None
                and getattr(ip, "scope_id", None) is None):
            return ip
    raise base.ProbeFailure("LONDON_ORIGIN_ADDRESS_UNAVAILABLE")


def curl_args(source, destination):
    endpoint = f"[{destination}]" if destination.version == 6 else str(destination)
    return ("/usr/bin/curl", "-q", "-" + str(source.version), "--noproxy", "*", "--proto", "=https",
            "--resolve", f"{HOST}:443:{endpoint}", "--interface", str(source), "--http1.1",
            "--silent", "--fail", "--connect-timeout", "3", "--header", "Accept-Encoding: identity")


def json_output(result, limit, error, base):
    if result.returncode or len(result.stdout) > limit:
        raise base.ProbeFailure(error)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise base.ProbeFailure(error)
    return value


def verify_address(args, expected, base):
    with tempfile.NamedTemporaryFile(prefix="proxy-origin-trace-") as body:
        result = base.command(str(PRLIMIT), "--fsize=1025:1025", "--", *args,
                              "--max-filesize", "1024", "--max-time", "6", "--output", body.name,
                              ORIGIN + "/getIP.php", timeout=7)
        raw = body.read(1025)
    if result.returncode or len(raw) > 1024:
        raise base.ProbeFailure("LONDON_ORIGIN_ADDRESS_UNVERIFIED")
    output = json.loads(raw)
    address = output.get("processedString")
    if not isinstance(address, str) or ipaddress.ip_address(address.strip()) != expected:
        raise base.ProbeFailure("LONDON_ORIGIN_EGRESS_MISMATCH")


def milliseconds(value, scale=1000):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        return None
    return round(value * scale, 2)


def https_stream(args, upload, payload, base, urls):
    tail = ("--max-time", "13", "--write-out", "%{json}")
    if upload:
        tail += ("--max-filesize", "8192", "--header", "Expect:",
                 "--header", "Content-Type: application/octet-stream",
                 "--data-binary", "@-", urls[1])
    else:
        tail += ("--max-filesize", str(HTTP_DOWNLOAD + 1), urls[0])
    # Older curl releases only enforce --max-filesize when the response has
    # a length header. Bound the output file even for a chunked response.
    limit = 8193 if upload else HTTP_DOWNLOAD + 1
    with tempfile.NamedTemporaryFile(prefix="proxy-origin-data-") as body:
        result = base.command(str(PRLIMIT), f"--fsize={limit}:{limit}", "--", *args,
                              "--output", body.name, *tail,
                              input=payload if upload else None, timeout=14)
    data = json_output(result, 8192, "LONDON_ORIGIN_HTTPS_TRANSFER_FAILED", base)
    expected = HTTP_UPLOAD if upload else HTTP_DOWNLOAD
    if data.get("http_code") != 200 or data.get("size_upload" if upload else "size_download") != expected:
        raise base.ProbeFailure("LONDON_ORIGIN_HTTPS_PAYLOAD_UNVERIFIED")
    return milliseconds(data.get("time_connect")), milliseconds(data.get("time_starttransfer"))


def https_wave(args, upload, payload, base, urls=CLOUVIDER_URLS):
    timestamp = utc()
    clock = monotonic()
    with ThreadPoolExecutor(STREAMS) as pool:
        futures = [pool.submit(https_stream, args, upload, payload, base, urls) for _ in range(STREAMS)]
        samples = [future.result() for future in futures]
    elapsed = max(monotonic() - clock, .001)
    total = STREAMS * (HTTP_UPLOAD if upload else HTTP_DOWNLOAD)
    connects = [connect for connect, _ in samples if connect is not None]
    first_bytes = [first for _, first in samples if first is not None]
    return {"started_at": timestamp, "elapsed_ms": round(elapsed * 1000, 2), "bytes": total,
            "aggregate_mbps": round(total * 8 / 1e6 / elapsed, 2), "tcp_retransmits": None,
            "tcp_connect_ms_median": statistics.median(connects) if connects else None,
            "first_byte_ms_median": statistics.median(first_bytes) if first_bytes else None}


def iperf_wave(source, destination, upload, base):
    started = utc()
    argv = [str(IPERF), "--client", str(destination), "-" + str(source.version), "--bind", str(source),
            "--port", IPERF_PORT, "--parallel", str(STREAMS), "--bytes", str(IPERF_REQUEST_BYTES),
            "--length", "32768", "--connect-timeout", "2500", "--json"]
    if not upload:
        argv.append("--reverse")
    result = base.command(*argv, timeout=15)
    data = json_output(result, 262144, "LONDON_ORIGIN_IPERF_TRANSFER_FAILED", base)
    if data.get("error"):
        raise base.ProbeFailure("LONDON_ORIGIN_IPERF_TRANSFER_FAILED")
    configuration = data.get("start", {}).get("test_start", {})
    if (configuration.get("protocol") != "TCP" or configuration.get("num_streams") != STREAMS
            or configuration.get("bytes") != IPERF_REQUEST_BYTES or configuration.get("reverse") != int(not upload)):
        raise base.ProbeFailure("LONDON_ORIGIN_IPERF_CONFIGURATION_UNVERIFIED")
    stats = data["end"]
    sender = stats["sum_sent"]
    receiver = stats["sum_received"]
    if any(type(row.get("bytes")) is not int or not 0 < row["bytes"] <= IPERF_SAMPLE_LIMIT
           for row in (sender, receiver)):
        raise base.ProbeFailure("LONDON_ORIGIN_IPERF_PAYLOAD_UNVERIFIED")
    retrans = sender.get("retransmits")
    rtts = [value for row in stats.get("streams", [])
            if (value := milliseconds(row.get("sender", {}).get("mean_rtt"), .001)) is not None and value > 0]
    rate = milliseconds(receiver.get("bits_per_second"), 1e-6)
    if rate is None or rate <= 0:
        raise base.ProbeFailure("LONDON_ORIGIN_IPERF_RATE_UNVERIFIED")
    return {"started_at": started, "elapsed_ms": milliseconds(receiver.get("seconds")),
            "bytes": receiver["bytes"], "aggregate_mbps": rate,
            "tcp_retransmits": retrans if type(retrans) is int and retrans >= 0 else None,
            "mean_rtt_ms_across_streams": round(statistics.mean(rtts), 2) if rtts else None}


def family_probe(source, expected, method, payload, base):
    report = {"family": source.version, "status": "UNAVAILABLE"}
    try:
        destination = resolve(source.version, base)
        base.route_check(source, destination)
        args = curl_args(source, destination)
        verify_address(args, expected, base)
        if method == "IPERF3_TCP":
            report["download"] = iperf_wave(source, destination, False, base)
            report["upload"] = iperf_wave(source, destination, True, base)
        else:
            report["download"] = https_wave(args, False, payload, base)
            report["upload"] = https_wave(args, True, payload, base)
        report["status"] = "OBSERVED"
    except base.ProbeFailure as error:
        report["reason"] = str(error)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        report["reason"] = "LONDON_ORIGIN_RESPONSE_UNVERIFIED"
    return report


def observe(catalog_path, base):
    """Use the VM-origin baseline module for checked primary identity and bounded subprocesses."""
    receipt = {"scope": "ORACLE_ORIGIN_TO_CLOUVIDER_LONDON_WITHOUT_CLIENT_TUNNEL", "started_at": utc()}
    try:
        if os.geteuid() != 0:
            raise base.ProbeFailure("LONDON_ORIGIN_ROOT_PREFLIGHT_REQUIRED")
        addresses = base.configured_addresses(Path(catalog_path))
        method = "IPERF3_TCP" if IPERF.is_file() else "LIBRESPEED_HTTPS"
        if not PRLIMIT.is_file():
            raise base.ProbeFailure("LONDON_ORIGIN_NO_BOUNDED_DOWNLOAD_RUNTIME")
    except base.ProbeFailure as error:
        return {**receipt, "status": "UNAVAILABLE", "reason": str(error)}
    except (OSError, ValueError, KeyError, TypeError):
        return {**receipt, "status": "UNAVAILABLE", "reason": "LONDON_ORIGIN_CONFIG_UNVERIFIED"}
    families = [family_probe(*pair, method, bytes(HTTP_UPLOAD) if method == "LIBRESPEED_HTTPS" else None, base)
                for pair in addresses]
    return {**receipt, "status": "OBSERVED" if all(row["status"] == "OBSERVED" for row in families) else "PARTIAL",
            "ended_at": utc(), "method": method, "streams": STREAMS,
            "nominal_payload_bytes": 4 * IPERF_REQUEST_BYTES if method == "IPERF3_TCP"
            else 2 * STREAMS * (HTTP_DOWNLOAD + HTTP_UPLOAD),
            "per_direction_measured_payload_ceiling_bytes": IPERF_SAMPLE_LIMIT if method == "IPERF3_TCP" else None,
            "families": families}


def observe_shared_path(catalog_path, base, performance):
    report = {"scope": "ORACLE_ORIGIN_PARALLEL_CLOUVIDER_AND_CLOUDFLARE_IPV4", "started_at": utc()}
    try:
        if os.geteuid() != 0 or not PRLIMIT.is_file():
            raise base.ProbeFailure("LONDON_SHARED_PATH_RUNTIME_UNAVAILABLE")
        (source, expected), _ = base.configured_addresses(catalog_path)
        london = resolve(4, base)
        cloudflare = base.resolve(4)
        for destination in (london, cloudflare):
            base.route_check(source, destination)
        london_curl = curl_args(source, london)
        cloudflare_curl = base.curl_base(source, cloudflare)
        verify_address(london_curl, expected, base)
        report["cloudflare_colo"] = base.trace(cloudflare_curl, expected)
        device = performance.physical_interface()
        report["queues"] = performance.queues(device)
        report["filter_counts"] = {}
        for direction in ("ingress", "egress"):
            filters = performance.json_command("tc", "-j", "filter", "show", "dev", device, direction)
            report["filter_counts"][direction] = len(filters) if isinstance(filters, list) else None
        for name in ("download", "upload"):
            upload = name == "upload"
            payload = bytes(HTTP_UPLOAD) if upload else None
            before = performance.load_snapshot(device)
            start = monotonic()
            with ThreadPoolExecutor(2) as pool:
                cf = pool.submit(https_wave, cloudflare_curl, upload, payload, base, CLOUDFLARE_URLS)
                lc = pool.submit(https_wave, london_curl, upload, payload, base, CLOUVIDER_URLS)
                samples = {"cloudflare": cf.result(), "clouvider": lc.result()}
            elapsed = max(monotonic() - start, .001)
            observed = performance.load_interval(before, performance.load_snapshot(device))
            report[name] = {"providers": samples, "aggregate_mbps": round(
                8 * sum(value["bytes"] for value in samples.values()) / elapsed / 1e6, 2),
                "elapsed_ms": round(elapsed * 1e3, 2),
                "physical_counters": observed["network_counter_deltas"][device],
                "cpu": observed["cpu"], "queue": observed["physical_queue"]}
        return {**report, "status": "OBSERVED", "ended_at": utc()}
    except base.ProbeFailure as error:
        return {**report, "status": "UNAVAILABLE", "reason": str(error)}
    except (OSError, ValueError, KeyError, TypeError):
        return {**report, "status": "UNAVAILABLE", "reason": "LONDON_SHARED_PATH_RESPONSE_UNVERIFIED"}


if __name__ == "__main__":
    folder = Path(__file__).resolve().parent
    sys.path.insert(0, str(folder))
    import vm_origin

    catalog = folder.parents[2] / "ops/network/endpoints.json"
    if sys.argv[1:] == ["--shared-path"]:
        import performance

        print(json.dumps(observe_shared_path(catalog, vm_origin, performance)))
    else:
        print(json.dumps(observe(catalog, vm_origin)))
