"""Adjust only the owned Headscale coordinator's map scheduling."""

import base64
import hashlib
import json
import os
import stat
from pathlib import Path


RECEIPT = Path("/var/lib/oracle-project-ops/tailscale-latency.json")
TUNING = {"node_store_batch_timeout": "50ms", "batch_change_delay": "100ms"}
MAX_CONFIG_BYTES = 8192
MAX_FAST_MAP_NODES = 64


def candidate(original):
    if len(original) > MAX_CONFIG_BYTES:
        raise ValueError("TAILNET_LATENCY_CONFIG_TOO_LARGE")
    config = json.loads(original)
    if not isinstance(config, dict):
        raise ValueError("TAILNET_LATENCY_INVALID_CONFIG")
    tuning = config.setdefault("tuning", {})
    if not isinstance(tuning, dict):
        raise ValueError("TAILNET_LATENCY_INVALID_CONFIG")
    tuning.update(TUNING)
    return (json.dumps(config, separators=(",", ":")) + "\n").encode()


def inspect(host):
    if os.geteuid() != 0 or not host.enabled():
        raise ValueError("TAILNET_LATENCY_OWNED_COORDINATOR_REQUIRED")
    host.command("systemctl", "is-active", "--quiet", host.HEADSCALE_SERVICE)
    version = host.command(host.BINARIES / "headscale", "version").stdout.splitlines()
    if not version or version[0] != b"headscale version v0.29.7":
        raise ValueError("TAILNET_LATENCY_UNSUPPORTED_COORDINATOR_VERSION")
    path = host.safe_target(host.HEADSCALE_CONFIG)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
        raise ValueError("TAILNET_LATENCY_INVALID_CONFIG")
    current = path.read_bytes()
    config = json.loads(current)
    if not isinstance(config, dict) or config.get("server_url") != host.ORIGIN:
        raise ValueError("TAILNET_LATENCY_INVALID_CONFIG")
    return current, stat.S_IMODE(info.st_mode)


def identity(host):
    host.verify_key()
    return json.loads(host.local_https("/key?v=148"))["publicKey"]


def exit_online(host, identifier, key):
    if identity(host) != key or host.running_exit() != identifier:
        return False
    nodes = host.headscale("nodes", "list")
    return (isinstance(nodes, list)
            and any(node.get("id") == identifier and node.get("online") is True for node in nodes)
            and host.route_approved(identifier) and host.controller_ready())


def restart(host, identifier, key):
    host.command("systemctl", "restart", host.HEADSCALE_SERVICE, timeout=30)
    host.wait_for(lambda: exit_online(host, identifier, key), deadline=45)


def receipt(host):
    path = host.safe_target(RECEIPT)
    if not path.exists():
        return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 2 * MAX_CONFIG_BYTES:
        raise ValueError("TAILNET_LATENCY_UNTRUSTED_RECEIPT")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {"schema", "original", "mode", "candidate_sha256", "applied"}:
        raise ValueError("TAILNET_LATENCY_UNTRUSTED_RECEIPT")
    original = base64.b64decode(value["original"], validate=True)
    mode = value["mode"]
    after = candidate(original)
    if (value["schema"] != 1 or type(value["applied"]) is not bool
            or type(mode) is not int or mode & ~0o755 or mode & 0o022
            or value["candidate_sha256"] != hashlib.sha256(after).hexdigest()):
        raise ValueError("TAILNET_LATENCY_UNTRUSTED_RECEIPT")
    return original, after, mode, value["applied"]


def save(host, original, after, mode, applied):
    journal = {"schema": 1, "original": base64.b64encode(original).decode("ascii"), "mode": mode,
               "candidate_sha256": hashlib.sha256(after).hexdigest(), "applied": applied}
    host.atomic(RECEIPT, json.dumps(journal).encode(), 0o600)


def change(host, apply):
    # The existing repository operations gate serializes calls on the host.
    current, mode = inspect(host)
    saved = receipt(host)
    if saved is None and not apply:
        print("PROJECT_TAILSCALE_LATENCY=NO_OWNED_CHANGE")
        return
    identifier = host.running_exit()
    public_key = identity(host)
    if identifier is None or not exit_online(host, identifier, public_key):
        raise ValueError("TAILNET_LATENCY_EXIT_NOT_READY")
    if apply:
        nodes = host.headscale("nodes", "list")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_FAST_MAP_NODES:
            raise ValueError("TAILNET_LATENCY_NODE_COUNT_OUTSIDE_PILOT")
        print(f"PROJECT_TAILSCALE_LATENCY_NODE_COUNT={len(nodes)}", flush=True)
    if saved is None:
        original, after = current, candidate(current)
        if json.loads(original) == json.loads(after):
            print("PROJECT_TAILSCALE_LATENCY=EXISTING_SETTINGS")
            return
    else:
        original, after, saved_mode, was_applied = saved
        if mode != saved_mode or current not in (original, after):
            raise ValueError("TAILNET_LATENCY_FOREIGN_CONFIG_CHANGE")
        if apply and was_applied and current == after:
            print("PROJECT_TAILSCALE_LATENCY=APPLIED", flush=True)
            return
    desired = after if apply else original
    save(host, original, after, mode, False)
    if current != desired:
        host.atomic(host.HEADSCALE_CONFIG, desired, mode)
    try:
        restart(host, identifier, public_key)
    except Exception:
        previous = original if apply else current
        host.atomic(host.HEADSCALE_CONFIG, previous, mode)
        try:
            restart(host, identifier, public_key)
        except Exception:
            raise ValueError("TAILNET_LATENCY_RECOVERY_REQUIRED") from None
        save(host, original, after, mode, previous == after)
        raise ValueError("TAILNET_LATENCY_RESTART_FAILED_RECOVERED") from None
    if apply:
        save(host, original, after, mode, True)
    else:
        RECEIPT.unlink()
    print("PROJECT_TAILSCALE_LATENCY=" + ("APPLIED" if apply else "RESTORED"), flush=True)
