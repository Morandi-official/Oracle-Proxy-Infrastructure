"""Authorizes the Tailscale exit using the existing account ledger."""

import hashlib
import ipaddress
import json
import math
import re
import socket
import struct
from contextlib import closing
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlsplit

from tailscale_control import HeadscaleControl
from tailscale_egress import (
    MAX_LEASE_SECONDS, apply_rules, index_peers, peer_counters, rate_rules, rate_table_exists, renew_rules,
)
from tailscale_registry import AdmissionRegistry, CoordinatorAccount

EXIT_SOCKET = "/run/oracle-proxy-tailnet-exit/tailscaled.sock"
MAX_STATUS_BYTES = 1024 * 1024


class ExitStatusConnection(HTTPConnection):
    def __init__(self, path):
        super().__init__("local-tailscaled.sock", timeout=2)
        self.path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            credentials = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", credentials)
            if uid != 0:
                raise OSError("UNTRUSTED_TAILSCALE_EXIT_SOCKET")
        except Exception:
            sock.close()
            raise
        self.sock = sock


def read_exit_status(path=EXIT_SOCKET):
    # The timer and first-device confirmation need only the daemon's LocalAPI.
    with closing(ExitStatusConnection(path)) as connection:
        connection.request("GET", "/localapi/v0/status")
        with connection.getresponse() as response:
            if response.status != 200:
                raise OSError("TAILSCALE_EXIT_UNAVAILABLE")
            body = response.read(MAX_STATUS_BYTES + 1)
    if len(body) > MAX_STATUS_BYTES:
        raise OSError("TAILSCALE_STATUS_TOO_LARGE")
    status = json.loads(body)
    if not isinstance(status, dict):
        raise ValueError("INVALID_TAILSCALE_PEER_STATUS")
    return status


class TailscaleGateway:
    def __init__(self, engine, configuration, registry, coordinator, observe, apply=apply_rules,
                 rate_exists=rate_table_exists):
        self.engine = engine
        self.registry = registry
        self.coordinator = coordinator
        self._observe = observe
        self._apply = apply
        self._rate_exists = rate_exists
        self._rate_plan = None
        self._last_ready_at = None
        self._accounts = {}
        self.profile = self._profile(configuration)
        # The firewall table must have been installed before exit route advertisement.
        self.close()

    @staticmethod
    def _profile(config):
        if set(config) != {"coordinator", "exit_node_id", "ipv4", "ipv6"}:
            raise ValueError("INVALID_TAILSCALE_CONFIGURATION")
        url = urlsplit(config["coordinator"])
        if (url.scheme != "https" or not url.hostname or
                not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", url.hostname) or
                url.netloc != url.hostname or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("INVALID_TAILSCALE_COORDINATOR")
        node_id = config["exit_node_id"]
        if type(node_id) is not int or not 0 < node_id < 2**63:
            raise ValueError("INVALID_TAILSCALE_EXIT")
        return {
            "coordinator": f"https://{url.hostname}",
            "exit_node_id": str(node_id),
            "ipv4": str(ipaddress.IPv4Address(config["ipv4"])),
            "ipv6": str(ipaddress.IPv6Address(config["ipv6"])),
        }

    @classmethod
    def load(cls, engine, directory, config_path):
        raw = json.loads(Path(config_path).read_text())
        coordinator = HeadscaleControl("/usr/local/libexec/oracle-proxy-tailnet/headscale",
                                      "/etc/oracle-proxy-tailnet/headscale.yaml")
        registry = AdmissionRegistry(Path(directory) / "tailscale-devices.sqlite3", coordinator, engine.now)
        return cls(engine, raw, registry, coordinator, read_exit_status)

    def close(self):
        self._last_ready_at = None
        self._apply(renew_rules({}))

    def ready(self):
        return self._last_ready_at is not None and 0 <= self.engine.now() - self._last_ready_at < MAX_LEASE_SECONDS

    def _eligible(self, user):
        return (user is not None and not self.engine.budget_state()["guard_blocked"]
                and self.engine.reason(user) == "active")

    def _account(self, user_id):
        if user_id not in self._accounts:
            username = "proxy-" + user_id.replace("-", "")
            self._accounts[user_id] = CoordinatorAccount(user_id, username, self.coordinator.account_id(username))
        return self._accounts[user_id]

    def profile_for(self, user_id, device, operation):
        user = self.engine.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if operation != "release" and not self._eligible(user):
            raise ValueError("TAILSCALE_ACCOUNT_NOT_ACTIVE")
        if not isinstance(device, str) or not re.fullmatch(r"[a-f0-9]{64}", device):
            raise ValueError("INVALID_PROXY_DEVICE_ID")
        account = self._account(user_id)
        device = hashlib.sha256(f"{user_id}:{device}".encode()).hexdigest()
        try:
            if operation == "release":
                try:
                    self.registry.revoke(account, device)
                finally:
                    self.refresh()
                return {"released": True}
            stored = self.registry.cached(account, device)
            key = None
            if operation == "confirm":
                node = self.registry.find(account, device)
                if node is None or node.node_id not in self.refresh():
                    raise ValueError("TAILSCALE_ENROLLMENT_PENDING")
            elif operation in ("profile", "retry_profile"):
                if not stored or stored.node_id is None:
                    if stored and self.registry.find(account, device):
                        self.refresh()
                    elif self.registry.device_count(account, excluding=device) >= self.engine.device_limit(user_id):
                        raise ValueError("DEVICE_LIMIT_EXCEEDED")
                    else:
                        key = self.registry.issue(account, device, retry_pending=operation == "retry_profile")
            else:
                raise ValueError("INVALID_OPERATION")
        except PermissionError as error:
            raise ValueError(str(error)) from None
        rate_limited = any(value is not None for value in self.engine.rate(user_id).values())
        return {**self.profile, "enrollment_key": key, "rate_limited": rate_limited}

    def refresh(self):
        """Record observed bytes once and renew only coordinator-bound addresses."""
        try:
            status = self._observe()
            if status.get("BackendState") != "Running" or (status.get("Self") or {}).get("ID") != self.profile["exit_node_id"]:
                raise OSError("TAILSCALE_EXIT_UNAVAILABLE")
            peers = index_peers(status)
            engine = self.engine
            active = []
            engine.db.execute("SAVEPOINT tailscale_usage")
            try:
                for binding in self.registry.bindings():
                    sample = peer_counters(peers, binding.node_id, binding.addresses)
                    if sample is None:
                        continue
                    name = f"tailscale:{binding.node_id}"
                    old = engine.db.execute("SELECT rx,tx FROM counters WHERE key=?", (name,)).fetchone()
                    delta = tuple(value if not old or value < old[index] else value - old[index]
                                  for index, value in enumerate(sample))
                    engine.db.execute("INSERT OR REPLACE INTO counters VALUES (?,?,?,?)",
                                      (name, *sample, "tailscale"))
                    if delta != (0, 0):
                        engine.add_usage("user", binding.account_id, *delta)
                    active.append(binding)
                engine.db.execute("RELEASE tailscale_usage")
            except Exception:
                engine.db.execute("ROLLBACK TO tailscale_usage")
                engine.db.execute("RELEASE tailscale_usage")
                raise

            leases = {}
            authorized_nodes = set()
            rate_addresses = {}
            for binding in active:
                user = engine.db.execute("SELECT * FROM users WHERE id=?", (binding.account_id,)).fetchone()
                if not self._eligible(user):
                    continue
                seconds = MAX_LEASE_SECONDS
                if user["expires"] is not None:
                    seconds = min(seconds, math.floor(user["expires"] - engine.now()))
                if seconds > 0:
                    authorized_nodes.add(binding.node_id)
                    leases.update({address: seconds for address in binding.addresses})
                    rate_addresses.setdefault(binding.account_id, set()).update(binding.addresses)
            plan = tuple(sorted((row["slot"], row["download_bps"], row["upload_bps"],
                                 tuple(sorted(rate_addresses[row["user_id"]])))
                                for row in engine.db.execute("SELECT * FROM user_rates")
                                if row["user_id"] in rate_addresses
                                and (row["download_bps"] is not None or row["upload_bps"] is not None)))
            changed = plan != self._rate_plan
            policy = rate_rules(plan, self._rate_exists()) if changed else ""
            self._apply(policy + renew_rules(leases))
            self._rate_plan = plan
            self._last_ready_at = engine.now()
            return authorized_nodes
        except Exception:
            self.close()
            raise
