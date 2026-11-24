"""Persistent association between an authenticated Proxy device and a tailnet node."""

import re
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass


@dataclass(frozen=True)
class CoordinatorAccount:
    account_id: str
    username: str
    coordinator_id: int

    def __post_init__(self):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", self.account_id):
            raise ValueError("INVALID_PROXY_ACCOUNT_ID")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", self.username):
            raise ValueError("INVALID_COORDINATOR_USERNAME")
        if type(self.coordinator_id) is not int or not 0 < self.coordinator_id < 2**63:
            raise ValueError("INVALID_COORDINATOR_ACCOUNT_ID")


class AdmissionRegistry:
    """Callers authenticate and check Proxy account and device policy first."""

    def __init__(self, path, coordinator, now=time.time):
        self._path = path
        self._coordinator = coordinator
        self._now = now
        with closing(self._open()) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS tailscale_admission (
                    device TEXT PRIMARY KEY,
                    account TEXT NOT NULL,
                    username TEXT NOT NULL,
                    coordinator_id INTEGER NOT NULL,
                    ticket INTEGER NOT NULL UNIQUE,
                    issued_at INTEGER NOT NULL,
                    node INTEGER UNIQUE,
                    ipv4 TEXT UNIQUE,
                    ipv6 TEXT UNIQUE,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    coordinator_clean INTEGER NOT NULL DEFAULT 0
                )
            """)

    def _open(self):
        db = sqlite3.connect(self._path, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    @contextmanager
    def _transaction(self):
        with closing(self._open()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    @staticmethod
    def _record(db, account, device):
        if not re.fullmatch(r"[a-f0-9]{64}", device):
            raise ValueError("INVALID_PROXY_DEVICE_ID")
        row = db.execute("SELECT * FROM tailscale_admission WHERE device=?", (device,)).fetchone()
        if row and (row["account"], row["username"], row["coordinator_id"]) != (
            account.account_id, account.username, account.coordinator_id,
        ):
            raise PermissionError("TAILSCALE_DEVICE_OWNER_MISMATCH")
        return row

    def _node_for(self, row):
        node = self._coordinator.find_node(row["username"], row["coordinator_id"], row["ticket"])
        if node and row["node"] is not None and (
            node.node_id, *node.addresses
        ) != (row["node"], row["ipv4"], row["ipv6"]):
            raise OSError("TAILSCALE_NODE_BINDING_CHANGED")
        return node

    def issue(self, account, device):
        with self._transaction() as db:
            row = self._record(db, account, device)
            now = int(self._now())
            if row:
                if row["revoked"]:
                    raise PermissionError("TAILSCALE_DEVICE_REVOKED")
                if row["node"] is not None or self._node_for(row) is not None:
                    raise ValueError("TAILSCALE_DEVICE_ALREADY_REGISTERED")
                if now - row["issued_at"] < self._coordinator.ticket_lifetime_seconds:
                    raise ValueError("TAILSCALE_ENROLLMENT_PENDING")
                self._coordinator.expire_ticket(row["ticket"])
                if self._node_for(row) is not None:
                    raise ValueError("TAILSCALE_DEVICE_ALREADY_REGISTERED")
            admission = self._coordinator.issue(account.coordinator_id)
            db.execute(
                """INSERT INTO tailscale_admission(device, account, username, coordinator_id, ticket, issued_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(device) DO UPDATE SET ticket=excluded.ticket, issued_at=excluded.issued_at""",
                (device, account.account_id, account.username, account.coordinator_id,
                 admission.ticket_id, int(self._now())),
            )
            return admission.credential

    def find(self, account, device):
        with self._transaction() as db:
            row = self._record(db, account, device)
            if not row or row["revoked"]:
                return None
            node = self._node_for(row)
            if node and row["node"] is None:
                db.execute(
                    "UPDATE tailscale_admission SET node=?, ipv4=?, ipv6=? WHERE device=?",
                    (node.node_id, *node.addresses, device),
                )
            return node

    def revoke(self, account, device):
        with self._transaction() as db:
            row = self._record(db, account, device)
            if not row or row["coordinator_clean"]:
                return
            db.execute("UPDATE tailscale_admission SET revoked=1 WHERE device=?", (device,))

        # A failed coordinator operation leaves a durable local revocation.
        # Expire the ticket before looking for a node so it cannot be consumed mid-revocation.
        self._coordinator.expire_ticket(row["ticket"])
        node = self._node_for(row)
        if node:
            self._coordinator.revoke(node)
        with self._transaction() as db:
            db.execute("UPDATE tailscale_admission SET coordinator_clean=1 WHERE device=?", (device,))
