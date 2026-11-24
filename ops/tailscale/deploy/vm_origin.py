"""A bounded, credential-free throughput control from the active Oracle origin."""

import concurrent.futures
import ipaddress
import json
import os
import re
import stat
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


HOST = "speed.cloudflare.com"
ORIGIN = "https://" + HOST
PROFILE = Path("/etc/oracle-proxy-control/tailscale.json")
STREAMS = 4
DOWNLOAD_BYTES = 8 * 1024 * 1024
UPLOAD_BYTES = 4 * 1024 * 1024
DEVICE = "enp0s6"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
TOTAL_PAYLOAD_LIMIT = 2 * STREAMS * (DOWNLOAD_BYTES + UPLOAD_BYTES)


class ProbeFailure(Exception):
    pass


def command(*args, input=None, timeout):
    try:
        return subprocess.run(args, input=input, capture_output=True, timeout=timeout, env=ENV)
    except (OSError, subprocess.SubprocessError):
        raise ProbeFailure("LOCAL_COMMAND_UNAVAILABLE") from None


def manifest(path, *, installed=False):
    if installed:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ProbeFailure("ORIGIN_PROFILE_UNTRUSTED")
    with path.open("rb") as f:
        raw = f.read(4097)
    if len(raw) > 4096:
        raise ProbeFailure("ORIGIN_CONFIG_TOO_LARGE")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ProbeFailure("ORIGIN_CONFIG_INVALID")
    return result


def configured_addresses(catalog_path):
    catalog = manifest(catalog_path)
    profile = manifest(PROFILE, installed=True)
    if (catalog.get("interface") != DEVICE or catalog.get("active") != "primary"
            or catalog.get("api_host") != "vpn-admin.morandi.dpdns.org"
            or profile.get("coordinator") != "https://vpn-admin.morandi.dpdns.org"):
        raise ProbeFailure("ORIGIN_PRIMARY_UNVERIFIED")
    primary = catalog["primary"]
    source4 = ipaddress.IPv4Address(primary["private_ipv4"])
    expected4 = ipaddress.IPv4Address(profile["ipv4"])
    expected6 = ipaddress.IPv6Address(profile["ipv6"])
    if (expected4 != ipaddress.IPv4Address(primary["public_ipv4"]) or not expected4.is_global
            or not expected6.is_global or expected6.ipv4_mapped is not None or expected6.scope_id is not None
            or source4 not in ipaddress.IPv4Network(catalog["subnet"])):
        raise ProbeFailure("ORIGIN_EGRESS_UNVERIFIED")
    return (source4, expected4), (expected6, expected6)


def resolve(family):
    query = "ahostsv4" if family == 4 else "ahostsv6"
    result = command("/usr/bin/getent", query, HOST, timeout=5)
    if result.returncode or len(result.stdout) > 16384:
        raise ProbeFailure("ORIGIN_RESOLUTION_FAILED")
    for row in result.stdout.decode("ascii").splitlines():
        fields = row.split()
        if not fields:
            continue
        address = ipaddress.ip_address(fields[0])
        if (address.version == family and address.is_global
                and getattr(address, "ipv4_mapped", None) is None
                and getattr(address, "scope_id", None) is None):
            return address
    raise ProbeFailure("ORIGIN_ADDRESS_UNAVAILABLE")


def route_check(source, destination):
    result = command("/usr/sbin/ip", "-j", "-" + str(source.version), "route", "get", str(destination),
                     "from", str(source), timeout=4)
    if result.returncode or len(result.stdout) > 4096:
        raise ProbeFailure("ORIGIN_ROUTE_UNAVAILABLE")
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("dev") != DEVICE:
        raise ProbeFailure("ORIGIN_ROUTE_UNVERIFIED")


def curl_base(source, destination):
    host_ip = f"[{destination}]" if destination.version == 6 else str(destination)
    return ("/usr/bin/curl", "-q", "-" + str(source.version), "--noproxy", "*", "--proto", "=https",
            "--resolve", HOST + ":443:" + host_ip, "--interface", str(source), "--http1.1",
            "--silent", "--show-error", "--fail", "--connect-timeout", "4",
            "--header", "Accept-Encoding: identity")


def trace(base, expected):
    result = command(*base, "--max-time", "8", "--max-filesize", "8192",
                     ORIGIN + "/cdn-cgi/trace", timeout=9)
    if result.returncode or len(result.stdout) > 8192:
        raise ProbeFailure("ORIGIN_TRACE_UNAVAILABLE")
    lines = result.stdout.decode("ascii").splitlines()
    seen = [line[3:] for line in lines if line.startswith("ip=")]
    if len(seen) != 1 or ipaddress.ip_address(seen[0]) != expected:
        raise ProbeFailure("ORIGIN_OBSERVED_IP_MISMATCH")
    colo = next((line[5:] for line in lines if line.startswith("colo=")), "")
    return colo if re.fullmatch(r"[A-Z]{3}", colo) else None


def transfer(base, uploading, data):
    expected = UPLOAD_BYTES if uploading else DOWNLOAD_BYTES
    command_args = (*base, "--max-time", "17", "--output", "/dev/null", "--write-out", "%{json}")
    if uploading:
        command_args += ("--max-filesize", "32768", "--header", "Expect:", "--header",
                         "Content-Type: application/octet-stream", "--data-binary", "@-", ORIGIN + "/__up")
    else:
        command_args += ("--max-filesize", str(expected), ORIGIN + "/__down?bytes=" + str(expected))
    result = command(*command_args, input=data, timeout=19)
    if result.returncode or len(result.stdout) > 8192:
        raise ProbeFailure("ORIGIN_TRANSFER_FAILED")
    row = json.loads(result.stdout)
    if not 200 <= row.get("http_code", 0) < 300:
        raise ProbeFailure("ORIGIN_TRANSFER_HTTP_FAILED")
    field = "size_upload" if uploading else "size_download"
    if row.get(field) != expected:
        raise ProbeFailure("ORIGIN_TRANSFER_LENGTH_MISMATCH")
    return row["time_starttransfer"] * 1000


def wave(base, uploading, data):
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=STREAMS) as pool:
        results = [pool.submit(transfer, base, uploading, data if uploading else None) for _ in range(STREAMS)]
        first_byte_ms = [result.result() for result in results]
    elapsed = max(time.monotonic() - started, .001)
    total = STREAMS * (UPLOAD_BYTES if uploading else DOWNLOAD_BYTES)
    return {"streams": STREAMS, "bytes": total, "elapsed_ms": round(elapsed * 1000, 2),
            "aggregate_mbps": round(total * 8 / 1_000_000 / elapsed, 2),
            "median_response_start_ms": round(statistics.median(first_byte_ms), 2)}


def family_probe(source, expected, data):
    result = {"family": source.version, "status": "UNAVAILABLE"}
    try:
        destination = resolve(source.version)
        route_check(source, destination)
        base = curl_base(source, destination)
        result["cloudflare_colo"] = trace(base, expected)
        result["download"] = wave(base, False, None)
        result["upload"] = wave(base, True, data)
        result["status"] = "OBSERVED"
    except ProbeFailure as error:
        result["reason"] = str(error)
    except (OSError, ValueError, KeyError, TypeError):
        result["reason"] = "ORIGIN_RESPONSE_UNVERIFIED"
    return result


def observe(catalog_path):
    """Call from a fixed preflight including the trusted repository catalog path."""
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = {"scope": "ORACLE_ORIGIN_TO_CLOUDFLARE_WITHOUT_CLIENT_TUNNEL",
              "started_at": started_at, "payload_limit_bytes": TOTAL_PAYLOAD_LIMIT}
    try:
        if os.geteuid() != 0:
            raise ProbeFailure("ORIGIN_ROOT_PREFLIGHT_REQUIRED")
        addresses = configured_addresses(Path(catalog_path))
    except ProbeFailure as error:
        return {**result, "status": "UNAVAILABLE", "reason": str(error)}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "status": "UNAVAILABLE", "reason": "ORIGIN_CONFIG_UNVERIFIED"}
    data = bytes(UPLOAD_BYTES)
    families = [family_probe(*pair, data) for pair in addresses]
    return {**result, "status": "OBSERVED" if all(row["status"] == "OBSERVED" for row in families) else "PARTIAL",
            "ended_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "families": families}


if __name__ == "__main__":
    catalog = Path(__file__).resolve().parents[3] / "ops/network/endpoints.json"
    print(json.dumps(observe(catalog)))
