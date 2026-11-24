"""Default-deny forwarding leases for the dedicated Linux Tailscale exit."""

import argparse
import ipaddress
import subprocess

TABLE = "oracle_proxy_tailscale"
RATE_TABLE = "oracle_proxy_tailscale_rates"
INTERFACE = "tailscale0"
POOLS = {
    4: ipaddress.ip_network("100.64.0.0/10"),
    6: ipaddress.ip_network("fd7a:115c:a1e0::/48"),
}
MAX_LEASE_SECONDS = 15
MAX_ADDRESSES = 2048
MAX_COUNTER_BYTES = 2**63 - 1


def install_rules():
    return f"""
create table inet {TABLE}
add set inet {TABLE} authorized4 {{ type ipv4_addr; flags timeout; size {MAX_ADDRESSES}; }}
add set inet {TABLE} authorized6 {{ type ipv6_addr; flags timeout; size {MAX_ADDRESSES}; }}
add chain inet {TABLE} inbound {{ type filter hook input priority -10; policy accept; }}
add rule inet {TABLE} inbound iifname "{INTERFACE}" drop
add chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}
add rule inet {TABLE} forward iifname "{INTERFACE}" oifname "{INTERFACE}" drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip6 daddr {{ ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, fc00::/7, fe80::/10, ff00::/8 }} drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip saddr != @authorized4 drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip6 saddr != @authorized6 drop
add rule inet {TABLE} forward oifname "{INTERFACE}" ip daddr != @authorized4 drop
add rule inet {TABLE} forward oifname "{INTERFACE}" ip6 daddr != @authorized6 drop
"""


def replace_rules(addresses, seconds):
    return renew_rules({address: seconds for address in addresses})


def renew_rules(leases):
    by_family = {4: {}, 6: {}}
    for address, seconds in leases.items():
        if type(seconds) is not int or not 1 <= seconds <= MAX_LEASE_SECONDS:
            raise ValueError("INVALID_TAILSCALE_LEASE")
        parsed = ipaddress.ip_address(address)
        if getattr(parsed, "scope_id", None) is not None or parsed not in POOLS[parsed.version]:
            raise ValueError("INVALID_TAILNET_ADDRESS")
        by_family[parsed.version][parsed] = seconds
    if sum(map(len, by_family.values())) > MAX_ADDRESSES:
        raise ValueError("TOO_MANY_TAILNET_ADDRESSES")

    commands = []
    for family, parsed in by_family.items():
        name = f"authorized{family}"
        commands.append(f"flush set inet {TABLE} {name}")
        if parsed:
            elements = ", ".join(f"{address} timeout {parsed[address]}s" for address in sorted(parsed))
            commands.append(f"add element inet {TABLE} {name} {{ {elements} }}")
    return "\n".join(commands) + "\n"


def apply_rules(rules):
    # nft applies the whole batch atomically. An unsuccessful refresh leaves
    # the preceding short-lived leases to expire in the kernel.
    subprocess.run(
        ["/usr/sbin/nft", "-f", "-"],
        input=rules,
        text=True,
        check=True,
        timeout=8,
    )


def rate_table_exists():
    result = subprocess.run(["/usr/sbin/nft", "list", "table", "inet", RATE_TABLE],
                            capture_output=True, timeout=3, check=False)
    if result.returncode and b"No such file or directory" not in result.stderr:
        raise OSError("TAILSCALE_RATE_POLICY_UNAVAILABLE")
    return result.returncode == 0


def rate_rules(plan, existing):
    # Rebuild atomically only when the per-user rates or device addresses change.
    # All devices and both IP families of one account share each direction's bucket.
    commands = [f"delete table inet {RATE_TABLE}"] if existing else []
    if not plan:
        return "\n".join(commands) + "\n" if commands else ""
    commands.extend((
        f"create table inet {RATE_TABLE}",
        f"add chain inet {RATE_TABLE} forward {{ type filter hook forward priority -9; policy accept; }}",
    ))
    for slot, down, up, addrs in plan:
        if type(slot) is not int or not 1 <= slot <= 256:
            raise ValueError("INVALID_TAILSCALE_RATE_SLOT")
        addresses = tuple(ipaddress.ip_address(address) for address in addrs)
        if any(address not in POOLS[address.version] or getattr(address, "scope_id", None) is not None for address in addresses):
            raise ValueError("INVALID_TAILNET_ADDRESS")
        for rate, iface, field in ((down, "oifname", "daddr"), (up, "iifname", "saddr")):
            if rate is None:
                continue
            if type(rate) is not int or not 100_000 <= rate <= 10_000_000_000:
                raise ValueError("INVALID_TAILSCALE_RATE")
            bucket = f"{field}_{slot}"
            commands.append(f"add limit inet {RATE_TABLE} {bucket} {{ rate over {rate // 8} bytes/second burst {max(16_384, rate // 80)} bytes; }}")
            for family, protocol in ((4, "ip"), (6, "ip6")):
                hosts = ", ".join(str(address) for address in addresses if address.version == family)
                if hosts:
                    commands.append(f'add rule inet {RATE_TABLE} forward {iface} "{INTERFACE}" {protocol} {field} {{ {hosts} }} limit name "{bucket}" drop')
    return "\n".join(commands) + "\n"


def node_counters(status, node_id, addresses):
    """Read an exit-side byte sample for the coordinator-verified node."""
    if status.get("BackendState") != "Running":
        return None
    return peer_counters(index_peers(status), node_id, addresses)


def index_peers(status):
    peers = status.get("Peer") or {}
    if not isinstance(peers, dict):
        raise ValueError("INVALID_TAILSCALE_PEER_STATUS")
    result = {}
    for peer in peers.values():
        node_id = peer.get("ID")
        if not isinstance(node_id, str) or node_id in result:
            raise ValueError("INVALID_TAILSCALE_PEER_ID")
        result[node_id] = peer
    return result


def peer_counters(peers, node_id, addresses):
    peer = peers.get(str(node_id))
    if peer is None:
        return None
    if set(peer.get("TailscaleIPs") or []) != set(addresses):
        raise ValueError("TAILSCALE_PEER_IDENTITY_MISMATCH")
    received, sent = (peer.get(name) for name in ("RxBytes", "TxBytes"))
    if any(type(value) is not int or not 0 <= value <= MAX_COUNTER_BYTES for value in (received, sent)):
        raise ValueError("INVALID_TAILSCALE_TRAFFIC_COUNTER")
    return received, sent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("install")
    replace = commands.add_parser("replace")
    replace.add_argument("--seconds", type=int, default=MAX_LEASE_SECONDS)
    replace.add_argument("addresses", nargs="*")
    args = parser.parse_args()
    if args.operation == "install":
        apply_rules(install_rules())
    else:
        apply_rules(replace_rules(args.addresses, args.seconds))


if __name__ == "__main__":
    main()
