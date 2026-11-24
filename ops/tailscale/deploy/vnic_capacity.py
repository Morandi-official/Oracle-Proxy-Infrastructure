"""Bounded OCI Networking telemetry for this Oracle Proxy VNIC."""

import json
import math
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


REGION = "uk-london-1"
NAMESPACE = "oci_vcn"
MINUTE = timedelta(minutes=1)
REPO = Path(__file__).resolve().parents[3]
METRICS = (
    ("ingress", "VnicFromNetworkBytes", "byte"),
    ("egress", "VnicToNetworkBytes", "byte"),
    ("ingress_throttle", "VnicIngressDropsThrottle", "packet"),
    ("egress_throttle", "VnicEgressDropsThrottle", "packet"),
)


def metric_error(error):
    status = getattr(error, "status", None)
    code = getattr(error, "code", None)
    allowed = {
        "BadRequest", "InternalError", "InvalidParameter", "InvalidTimeInterval",
        "NotAuthenticated", "NotAuthorized", "NotAuthorizedOrNotFound",
        "ServiceUnavailable", "TooManyRequests",
    }
    return {"status": "API_ERROR", "http_status": status if type(status) is int and 100 <= status <= 599 else None,
            "oci_code": code if isinstance(code, str) and code in allowed else None}


def primary_vnic():
    sys.path.insert(0, str(REPO / "server/admin-oracle/control"))
    from oci_usage import metadata

    config = json.loads((REPO / "ops/network/endpoints.json").read_bytes())
    instance = metadata("instance/")
    compartment = instance["compartmentId"]
    matches = [row["vnicId"] for row in metadata("vnics/")
               if row.get("privateIp") == config["primary"]["private_ipv4"]]
    # This production primary subnet and its instance are in the root compartment.
    if (config.get("active") != "primary" or config.get("interface") != "enp0s6"
            or (instance.get("canonicalRegionName") or instance.get("region")) != REGION
            or not re.fullmatch(r"ocid1\.tenancy\.oc1\.\.[a-z0-9]+", compartment)
            or len(matches) != 1
            or not re.fullmatch(r"ocid1\.vnic\.oc1\.uk-london-1\.[a-z0-9]+", matches[0])):
        raise ValueError("UNVERIFIED_PRIMARY_VNIC_SCOPE")
    return compartment, matches[0]


def parse_samples(streams, name, start, end, compartment, vnic):
    if not isinstance(streams, list) or len(streams) > 1:
        raise ValueError("UNEXPECTED_STREAM_COUNT")
    if not streams:
        return {}
    stream = streams[0]
    if (stream.name != name or stream.namespace != NAMESPACE or stream.compartment_id != compartment
            or stream.dimensions.get("resourceId") != vnic):
        raise ValueError("UNEXPECTED_STREAM")
    expected = int((end - start) / MINUTE)
    points = stream.aggregated_datapoints
    if not isinstance(points, list) or len(points) > expected + 2:
        raise ValueError("UNEXPECTED_SAMPLE_COUNT")
    samples = {}
    for point in points:
        end_at = point.timestamp
        if not isinstance(end_at, datetime) or end_at.utcoffset() != timedelta(0) or end_at.second or end_at.microsecond:
            raise ValueError("UNEXPECTED_TIMESTAMP")
        if not start < end_at <= end:
            continue
        value = point.value
        if (type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 2**53
                or value != int(value) or end_at in samples):
            raise ValueError("UNEXPECTED_DATAPOINT")
        samples[end_at] = int(value)
    return samples


def describe(samples, expected, kind):
    if not samples:
        state = "NO_DATA"
    elif len(samples) != expected:
        state = "PARTIAL_COVERAGE"
    else:
        state = "OBSERVED"
    result = {"status": state, "samples": len(samples), "expected_samples": expected}
    if kind == "byte":
        result["peak_minute_average_mbps"] = round(max(samples.values()) * 8 / 60 / 1_000_000, 3) if samples else None
    else:
        result.update(packets_total=sum(samples.values()) if samples else None,
                      peak_packets_per_minute=max(samples.values()) if samples else None,
                      nonzero_minutes=sum(value > 0 for value in samples.values()) if samples else None)
    return result


def observe():
    now = datetime.now(timezone.utc)
    end = now.replace(second=0, microsecond=0) - 2 * MINUTE
    start = end - 30 * MINUTE
    record = {"start_utc": start.isoformat(), "end_utc": end.isoformat(),
              "queried_utc": now.isoformat(), "sample_seconds": 60, "metrics": {}, "minutes": []}
    if os.geteuid() != 0:
        return {**record, "status": "ROOT_PREFLIGHT_REQUIRED"}
    try:
        compartment, vnic = primary_vnic()
    except (ImportError, OSError, TypeError, KeyError, ValueError):
        return {**record, "status": "PRIMARY_VNIC_SCOPE_UNAVAILABLE"}
    os.environ["OCI_PYTHON_SDK_NO_SERVICE_IMPORTS"] = "true"
    try:
        from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
        from oci.monitoring import MonitoringClient
        from oci.monitoring.models import SummarizeMetricsDataDetails
        from oci.retry import NoneRetryStrategy
    except ImportError:
        return {**record, "status": "OCI_SDK_UNAVAILABLE"}
    retry = NoneRetryStrategy()
    try:
        signer = InstancePrincipalsSecurityTokenSigner(retry_strategy=retry, federation_client_retry_strategy=retry)
        if signer.tenancy_id != compartment:
            return {**record, "status": "OCI_IDENTITY_MISMATCH"}
        client = MonitoringClient({"region": REGION}, signer=signer, timeout=(3, 7), retry_strategy=retry)
    except Exception as error:
        return {**record, "status": "OCI_IDENTITY_UNAVAILABLE", "reason": metric_error(error)}
    expected = int((end - start) / MINUTE)
    observed = {}
    for key, name, kind in METRICS:
        details = SummarizeMetricsDataDetails(
            namespace=NAMESPACE,
            query=f'{name}[1m]{{resourceId="{vnic}"}}.sum()',
            start_time=start,
            end_time=min(now, end + timedelta(seconds=1)),
            resolution="1m",
        )
        try:
            result = client.summarize_metrics_data(
                compartment, details, compartment_id_in_subtree=False, retry_strategy=retry)
        except Exception as error:
            record["metrics"][key] = metric_error(error)
            if getattr(error, "status", None) in (401, 403, 404):
                # These four requests share service, namespace, and permission.
                break
            continue
        try:
            points = parse_samples(result.data, name, start, end, compartment, vnic)
        except (AttributeError, TypeError, ValueError, OverflowError):
            record["metrics"][key] = {"status": "UNEXPECTED_RESPONSE"}
            continue
        observed[key] = points
        record["metrics"][key] = describe(points, expected, kind)
    for key, _, _ in METRICS:
        record["metrics"].setdefault(key, {"status": "NOT_QUERIED"})
    for ending in sorted({mark for points in observed.values() for mark in points}):
        row = {"ending_utc": ending.isoformat()}
        for key, _, kind in METRICS:
            value = observed.get(key, {}).get(ending)
            if kind == "byte":
                row[f"{key}_minute_average_mbps"] = round(value * 8 / 60 / 1_000_000, 3) if value is not None else None
            else:
                row[f"{key}_dropped_packets"] = value
        record["minutes"].append(row)
    statuses = [value["status"] for value in record["metrics"].values()]
    record["status"] = ("OBSERVED" if all(state == "OBSERVED" for state in statuses) else
                        "PARTIAL" if record["minutes"] else "UNAVAILABLE")
    return record


if __name__ == "__main__":
    print(json.dumps(observe(), sort_keys=True))
