"""Authorizes the Tailscale exit using the existing account ledger."""

import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from tailscale_control import HeadscaleControl
from tailscale_egress import MAX_LEASE_SECONDS, apply_rules, index_peers, peer_counters, renew_rules
from tailscale_registry import AdmissionRegistry, CoordinatorAccount


class TailscaleGateway:
    def __init__(self, engine, configuration, registry, coordinator, observe, apply=apply_rules):
        self.engine = engine
        self.registry = registry
        self.coordinator = coordinator
        self._observe = observe
        self._apply = apply
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
        coordinator = HeadscaleControl("/usr/bin/headscale", "/etc/headscale/config.yaml")
        registry = AdmissionRegistry(Path(directory) / "tailscale-devices.sqlite3", coordinator, engine.now)
        return cls(engine, raw, registry, coordinator,
                   lambda: json.loads(engine.driver.command(["/usr/bin/tailscale", "status", "--json"]).stdout))

    def close(self):
        self._apply(renew_rules({}))

    def _eligible(self, user):
        return (user is not None and not self.engine.budget_state()["guard_blocked"]
                and self.engine.reason(user) == "active")

    def _rate_supported(self, user_id):
        # The legacy throughput classes only cover the legacy tunnel devices.
        return all(value is None for value in self.engine.rate(user_id).values())

    def _account(self, user_id):
        if user_id not in self._accounts:
            username = "proxy-" + user_id.replace("-", "")
            self._accounts[user_id] = CoordinatorAccount(user_id, username, self.coordinator.account_id(username))
        return self._accounts[user_id]

    def profile_for(self, user_id, device, operation):
        user = self.engine.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not self._eligible(user):
            raise ValueError("TAILSCALE_ACCOUNT_NOT_ACTIVE")
        if not self._rate_supported(user_id):
            raise ValueError("TAILSCALE_RATE_POLICY_UNAVAILABLE")
        if not isinstance(device, str) or not re.fullmatch(r"[a-f0-9]{64}", device):
            raise ValueError("INVALID_PROXY_DEVICE_ID")
        account = self._account(user_id)
        device = hashlib.sha256(f"{user_id}:{device}".encode()).hexdigest()
        try:
            stored = self.registry.cached(account, device)
            key = None
            if operation == "confirm":
                if not self.registry.find(account, device):
                    raise ValueError("TAILSCALE_ENROLLMENT_PENDING")
                self.refresh()
            elif operation == "profile":
                if not stored or stored.node_id is None:
                    if stored and self.registry.find(account, device):
                        self.refresh()
                    elif self.registry.device_count(account, excluding=device) >= self.engine.device_limit(user_id):
                        raise ValueError("DEVICE_LIMIT_EXCEEDED")
                    else:
                        key = self.registry.issue(account, device)
            else:
                raise ValueError("INVALID_OPERATION")
        except PermissionError as error:
            raise ValueError(str(error)) from None
        return {**self.profile, "enrollment_key": key}

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
            for binding in active:
                user = engine.db.execute("SELECT * FROM users WHERE id=?", (binding.account_id,)).fetchone()
                if not self._eligible(user) or not self._rate_supported(binding.account_id):
                    continue
                seconds = MAX_LEASE_SECONDS
                if user["expires"] is not None:
                    seconds = min(seconds, math.floor(user["expires"] - engine.now()))
                if seconds > 0:
                    leases.update({address: seconds for address in binding.addresses})
            self._apply(renew_rules(leases))
        except Exception:
            self.close()
            raise
