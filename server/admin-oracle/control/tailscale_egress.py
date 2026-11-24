"""Default-deny forwarding leases for the dedicated Linux Tailscale exit."""

import argparse
import ipaddress
import subprocess

TABLE = "oracle_proxy_tailscale"
INTERFACE = "tailscale0"
POOLS = {
    4: ipaddress.ip_network("100.64.0.0/10"),
    6: ipaddress.ip_network("fd7a:115c:a1e0::/48"),
}
MAX_LEASE_SECONDS = 15
MAX_ADDRESSES = 2048


def install_rules():
    return f"""
create table inet {TABLE}
add set inet {TABLE} authorized4 {{ type ipv4_addr; flags timeout; size {MAX_ADDRESSES}; }}
add set inet {TABLE} authorized6 {{ type ipv6_addr; flags timeout; size {MAX_ADDRESSES}; }}
add chain inet {TABLE} inbound {{ type filter hook input priority -10; policy accept; }}
add rule inet {TABLE} inbound iifname "{INTERFACE}" drop
add chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}
add rule inet {TABLE} forward iifname "{INTERFACE}" oifname "{INTERFACE}" drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip saddr != @authorized4 drop
add rule inet {TABLE} forward iifname "{INTERFACE}" ip6 saddr != @authorized6 drop
add rule inet {TABLE} forward oifname "{INTERFACE}" ip daddr != @authorized4 drop
add rule inet {TABLE} forward oifname "{INTERFACE}" ip6 daddr != @authorized6 drop
"""


def replace_rules(addresses, seconds):
    if type(seconds) is not int or not 1 <= seconds <= MAX_LEASE_SECONDS:
        raise ValueError("INVALID_TAILSCALE_LEASE")
    by_family = {4: set(), 6: set()}
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if getattr(parsed, "scope_id", None) is not None or parsed not in POOLS[parsed.version]:
            raise ValueError("INVALID_TAILNET_ADDRESS")
        by_family[parsed.version].add(parsed)
    if sum(map(len, by_family.values())) > MAX_ADDRESSES:
        raise ValueError("TOO_MANY_TAILNET_ADDRESSES")

    commands = []
    for family, parsed in by_family.items():
        name = f"authorized{family}"
        commands.append(f"flush set inet {TABLE} {name}")
        if parsed:
            elements = ", ".join(f"{address} timeout {seconds}s" for address in sorted(parsed))
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
