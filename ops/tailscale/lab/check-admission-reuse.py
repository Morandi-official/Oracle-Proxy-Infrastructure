"""Verify that completed revocations allow Headscale to recycle addresses."""

import hashlib
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "server/admin-oracle/control"))
from tailscale_control import Admission, BoundNode
from tailscale_registry import AdmissionRegistry, CoordinatorAccount, RETRY_PENDING_AFTER_SECONDS


class Coordinator:
    ticket_lifetime_seconds = 300

    def __init__(self):
        self.nodes = {}
        self.next_ticket = 0
        self.fail_revocation = False
        self.expired_tickets = []

    def issue(self, user_id):
        self.next_ticket += 1
        return Admission(user_id, self.next_ticket, "fixture")

    def find_node(self, username, user_id, ticket_id):
        return self.nodes.get(ticket_id)

    def expire_ticket(self, ticket_id):
        self.expired_tickets.append(ticket_id)

    def revoke(self, node):
        if self.fail_revocation:
            raise OSError("disposable coordinator unavailable")
        ticket = next(ticket for ticket, assigned in self.nodes.items() if assigned == node)
        del self.nodes[ticket]


def check_reuse(database):
    coordinator = Coordinator()
    account = CoordinatorAccount("fixture", "proxy-fixture", 1)
    registry = AdmissionRegistry(database, coordinator)
    recycled = ("100.100.46.2", "fd7a:115c:a1e0:46::2")
    reserved = ("100.100.46.3", "fd7a:115c:a1e0:46::3")

    def enroll(label, node):
        device = hashlib.sha256(label.encode()).hexdigest()
        registry.issue(account, device)
        coordinator.nodes[coordinator.next_ticket] = node
        assert registry.find(account, device) == node
        return device

    legacy_node = BoundNode(2, recycled)
    legacy = enroll("older clean revocation", legacy_node)
    # Model a release recorded before retired bindings freed their addresses.
    coordinator.revoke(legacy_node)
    with sqlite3.connect(database) as db:
        db.execute("UPDATE tailscale_admission SET revoked=1, coordinator_clean=1 WHERE device=?", (legacy,))

    pending_node = BoundNode(3, reserved)
    pending = enroll("failed revocation", pending_node)
    coordinator.fail_revocation = True
    try:
        registry.revoke(account, pending)
    except OSError:
        pass
    else:
        raise AssertionError("fixture did not exercise failed revocation")
    coordinator.fail_revocation = False

    registry = AdmissionRegistry(database, coordinator)
    assert registry.find(account, legacy) is None
    assert registry.find(account, pending) is None
    with sqlite3.connect(database) as db:
        expected = (1, 0, pending_node.node_id, *reserved)
        pending_row = db.execute("SELECT revoked, coordinator_clean, node, ipv4, ipv6 FROM tailscale_admission WHERE device=?",
                                 (pending,)).fetchone()
        assert pending_row == expected, "migration freed a binding whose cleanup failed"

    current = enroll("first use after Headscale restart", BoundNode(4, recycled))
    registry.revoke(account, current)
    enroll("use after a new clean revocation", BoundNode(5, recycled))

    registry.revoke(account, pending)
    enroll("use after successful cleanup retry", BoundNode(6, reserved))
    assert {binding.node_id for binding in registry.bindings()} == {5, 6}


def check_pending_retry(database):
    coordinator = Coordinator()
    account = CoordinatorAccount("fixture", "proxy-fixture", 1)
    other = CoordinatorAccount("other", "proxy-other", 2)
    device = hashlib.sha256(b"interrupted enrollment").hexdigest()
    now = 1000
    registry = AdmissionRegistry(database, coordinator, lambda: now)
    registry.issue(account, device)
    original = coordinator.next_ticket

    def rejects(owner, expected, *, retry_pending=True):
        try:
            registry.issue(owner, device, retry_pending=retry_pending)
        except (ValueError, PermissionError) as error:
            assert str(error) == expected, error
        else:
            raise AssertionError("unexpected enrollment")

    now += RETRY_PENDING_AFTER_SECONDS - 1
    rejects(account, "TAILSCALE_ENROLLMENT_PENDING")
    now += 1
    rejects(account, "TAILSCALE_ENROLLMENT_PENDING", retry_pending=False)
    rejects(other, "TAILSCALE_DEVICE_OWNER_MISMATCH")
    assert not coordinator.expired_tickets
    registry.issue(account, device, retry_pending=True)
    assert coordinator.expired_tickets == [original]
    assert coordinator.next_ticket == original + 1

    # A coordinator node registered immediately before retry keeps its identity.
    node = BoundNode(7, ("100.100.46.2", "fd7a:115c:a1e0:46::2"))
    coordinator.nodes[coordinator.next_ticket] = node
    now += coordinator.ticket_lifetime_seconds
    rejects(account, "TAILSCALE_DEVICE_ALREADY_REGISTERED")
    assert registry.find(account, device) == node
    assert coordinator.expired_tickets == [original]
    registry.revoke(account, device)
    rejects(account, "TAILSCALE_DEVICE_REVOKED")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="proxy-admission-reuse-") as directory:
        check_reuse(Path(directory) / "admission.sqlite")
        check_pending_retry(Path(directory) / "retry.sqlite")
    print("TAILSCALE_COMPLETED_REVOCATION_ADDRESS_REUSE=PASS")
    print("TAILSCALE_ABANDONED_ENROLLMENT_RETRY=PASS")
