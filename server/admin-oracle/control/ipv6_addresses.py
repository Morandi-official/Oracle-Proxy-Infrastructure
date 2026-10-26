"""Stable ULA allocation for product-owned peers; leaves legacy IPv4 unchanged."""
import ipaddress

NETWORK = ipaddress.IPv6Network('fd42:6f70:78:77::/64')
SERVER = ipaddress.IPv6Interface('fd42:6f70:78:77::1/64')


def enabled(networks):
    return any(ipaddress.ip_interface(value) == SERVER for value in networks)


def dual_addresses(addresses, networks):
    if not enabled(networks):
        return addresses
    hosts = [ipaddress.ip_interface(value) for value in addresses]
    ipv4 = [value for value in hosts if value.version == 4 and value.network.prefixlen == 32]
    if len(ipv4) != 1:
        raise ValueError('OWNED_IPV4_HOST_REQUIRED_FOR_IPV6')
    address = ipaddress.IPv6Address(int(NETWORK.network_address) + int(ipv4[0].ip))
    expected = str(address) + '/128'
    if any(value.version == 6 and str(value) != expected for value in hosts):
        raise ValueError('FOREIGN_OWNED_IPV6_ADDRESS')
    return [str(ipv4[0]), expected]
