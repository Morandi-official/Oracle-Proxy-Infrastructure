"""Use the product's Headscale adapter against the disposable coordinator."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "server/admin-oracle/control"))
from tailscale_control import HeadscaleControl
from tailscale_egress import node_counters


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("config")
    parser.add_argument("operation", choices=("issue", "find", "revoke", "absent", "traffic"))
    parser.add_argument("user_id", type=int)
    parser.add_argument("--username", default="admitted")
    parser.add_argument("--ticket-id", type=int)
    args = parser.parse_args()
    control = HeadscaleControl(args.binary, args.config)
    if args.operation == "issue":
        admission = control.issue(args.user_id)
        print(admission.ticket_id)
        print(admission.credential)
        return
    node = control.find_node(args.username, args.user_id, args.ticket_id)
    if args.operation == "absent":
        if node is not None:
            raise SystemExit("UNEXPECTED_HEADSCALE_NODE")
    elif node is None:
        raise SystemExit("HEADSCALE_NODE_NOT_FOUND")
    elif args.operation == "revoke":
        control.revoke(node)
    elif args.operation == "traffic":
        counters = node_counters(json.load(sys.stdin), node.node_id, node.addresses)
        if counters is None or min(counters) <= 0:
            raise SystemExit("TAILSCALE_NODE_TRAFFIC_NOT_OBSERVED")
    else:
        print(*node.addresses)


if __name__ == "__main__":
    main()
