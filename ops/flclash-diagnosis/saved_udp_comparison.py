"""Print an allowlisted summary of a single saved transport diagnosis."""
import hashlib
import json
import re
import sys

from issued_profile import Admin

TARGETS = ("15d3e2e1c31b67cbb1d2f28e9b32ddb3d6b5ee47894030264ecb1490f667b22b", "46e42b5db20d0485c66070e0bf073b62b835b85f4463feab238cd475395ebc71")

def extract(fields, data):
    return {name: data[name] for name in fields.split() if name in data}


def main():
    admin = Admin()
    rows = admin.api("/api/udp-diagnostics")["diagnostics"]
    selected = [row for row in rows if hashlib.sha256(row["id"].encode()).hexdigest() in TARGETS]
    if len(selected) != len(TARGETS):
        raise RuntimeError("SAVED_DIAGNOSTIC_NOT_FOUND")
    for row in sorted(selected, key=lambda row: row["started_at"]):
        report_summary(row)


def report_summary(row):
    report = row["report"]
    print("REPORT_TIME=" + str(row["started_at"]), flush=True)
    status = extract("server_capture_closed client_receive_layer physical_nic_observation", report)
    print("REPORT_STATUS=" + json.dumps(status, separators=(",", ":")), flush=True)
    for trial in report["trials"]:
        server = trial.get("server", {})
        client = trial.get("client", {})
        result = extract("address port verdict", trial)
        result["server"] = extract("server_started_at kernel_handshake_advanced index_correlation_available", server)
        result["capture"] = extract("capture_status ring_evictions socket_drops complete_observation rx_initiations tx_responses tx_cookies", server.get("capture", {}))
        result["client"] = extract("elapsed_ms error egress_verified", client)
        result["socket"] = extract("tx_initiations rx_responses rx_invalid rx_obsolete rx_cookies read_errors write_errors last_read_error last_write_error", client.get("counters", {}))
        print("REPORT_TRIAL=" + json.dumps(result, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = type(error).__name__
        print("REPORT_READBACK=" + code, flush=True)
        sys.exit(1)
