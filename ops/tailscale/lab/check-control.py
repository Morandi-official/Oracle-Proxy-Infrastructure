"""Use the product's Headscale adapter against the disposable coordinator."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "server/admin-oracle/control"))
from tailscale_control import HeadscaleControl
from tailscale_egress import node_counters
from tailscale_registry import AdmissionRegistry, CoordinatorAccount

DEVICE = hashlib.sha256(b"isolated-proxy-account-device").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("config")
    parser.add_argument("database")
    parser.add_argument("operation", choices=("issue", "find", "revoke", "absent", "traffic", "deny-owner", "pending"))
    parser.add_argument("user_id", type=int)
    parser.add_argument("--username", default="admitted")
    args = parser.parse_args()
    control = HeadscaleControl(args.binary, args.config)
    registry = AdmissionRegistry(args.database, control)
    account = CoordinatorAccount(args.username, args.username, args.user_id)
    if args.operation == "issue":
        print(registry.issue(account, DEVICE))
        return
    if args.operation == "deny-owner":
        try:
            registry.find(account, DEVICE)
        except PermissionError as error:
            if str(error) == "TAILSCALE_DEVICE_OWNER_MISMATCH":
                return
            raise
        raise SystemExit("UNEXPECTED_HEADSCALE_DEVICE_ACCESS")
    if args.operation == "pending":
        try:
            registry.issue(account, DEVICE)
        except ValueError as error:
            if str(error) == "TAILSCALE_ENROLLMENT_PENDING":
                return
            raise
        raise SystemExit("SECOND_ACTIVE_ENROLLMENT_ISSUED")
    if args.operation == "revoke":
        registry.revoke(account, DEVICE)
        return
    node = registry.find(account, DEVICE)
    if args.operation == "absent":
        if node is not None:
            raise SystemExit("UNEXPECTED_HEADSCALE_NODE")
    elif node is None:
        raise SystemExit("HEADSCALE_NODE_NOT_FOUND")
    elif args.operation == "traffic":
        counters = node_counters(json.load(sys.stdin), node.node_id, node.addresses)
        if counters is None or min(counters) <= 0:
            raise SystemExit("TAILSCALE_NODE_TRAFFIC_NOT_OBSERVED")
    else:
        print(*node.addresses)


if __name__ == "__main__":
    main()
