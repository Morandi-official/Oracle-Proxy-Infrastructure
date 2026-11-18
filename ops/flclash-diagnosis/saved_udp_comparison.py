"""Print an allowlisted summary of a single saved transport diagnosis."""
import hashlib
import json
import re
import sys

from issued_profile import Admin

TARGET = "f5316233aeb4d25e4335010f7ef8d7b30bf73d8a92eca47d1e1d42f664404a03"

def extract(fields, data):
    return {name: data[name] for name in fields.split() if name in data}


def main():
    admin = Admin()
    rows = admin.api("/api/udp-diagnostics")["diagnostics"]
    selected = [row for row in rows if hashlib.sha256(row["id"].encode()).hexdigest() == TARGET]
    if len(selected) != 1:
        raise RuntimeError("SAVED_DIAGNOSTIC_NOT_FOUND")
    row = selected[0]
    report = row["report"]
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
    control = admin.api("/api/control")
    print("PRODUCTION_CONTROL=" + json.dumps({"error_free": not control.get("error"), "backup_key_ready": bool(control.get("endpoint_public_keys", {}).get("backup"))}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = type(error).__name__
        print("REPORT_READBACK=" + code, flush=True)
        sys.exit(1)
