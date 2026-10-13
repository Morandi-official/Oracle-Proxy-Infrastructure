#!/usr/bin/env bash
# G13: genuine Linux WireGuard kernel tunnel across three ISOLATED network
# namespaces on a disposable, hosted CI VM. Never touches host routes or WFP.
set -Eeuo pipefail

if [[ "${1:-}" != '--ci-disposable-netns-only' || "${GITHUB_ACTIONS:-}" != true ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != Linux ||
      "$(id -u)" != 0 ]]; then
  echo 'REFUSED: requires explicit opt-in on a disposable GitHub-hosted Linux runner as root' >&2
  exit 4
fi
for cmd in ip wg wg-quick tcpdump ping python3 awk; do
  command -v "$cmd" >/dev/null || { echo "Missing lab dependency: $cmd" >&2; exit 4; }
done

umask 077
work=$(mktemp -d)
a="opg13-a-$$"; m="opg13-m-$$"; b="opg13-b-$$"
capture_pid=''; dns_pid=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$capture_pid" ]]; then kill -INT "$capture_pid" 2>/dev/null || :; wait "$capture_pid" 2>/dev/null || :; fi
  if [[ -n "$dns_pid" ]]; then kill "$dns_pid" 2>/dev/null || :; wait "$dns_pid" 2>/dev/null || :; fi
  for ns in "$a" "$m" "$b"; do ip netns delete "$ns" 2>/dev/null || :; done
  rm -rf -- "$work"
  if [[ "$status" != 0 ]]; then echo "G13_FAIL: isolated namespace lab exit=$status" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

# The Linux host's own interfaces, routing, resolver and firewall are untouched.
for ns in "$a" "$m" "$b"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add opg13-va type veth peer name opg13-ma
ip link add opg13-vb type veth peer name opg13-mb
ip link set opg13-va netns "$a"; ip link set opg13-ma netns "$m"
ip link set opg13-vb netns "$b"; ip link set opg13-mb netns "$m"
ip -n "$a" addr add 198.18.0.2/30 dev opg13-va
ip -n "$m" addr add 198.18.0.1/30 dev opg13-ma
ip -n "$m" addr add 198.18.0.5/30 dev opg13-mb
ip -n "$b" addr add 198.18.0.6/30 dev opg13-vb
for pair in "$a opg13-va" "$m opg13-ma" "$m opg13-mb" "$b opg13-vb"; do
  read -r ns iface <<< "$pair"; ip -n "$ns" link set "$iface" up
done
ip netns exec "$m" sysctl -qw net.ipv4.ip_forward=1
ip -n "$a" route add 198.18.0.6/32 via 198.18.0.1
ip -n "$b" route add 198.18.0.2/32 via 198.18.0.5

# Private keys exist only in a root-owned ephemeral directory, never logs/artifacts.
wg genkey > "$work/a.key"; wg pubkey < "$work/a.key" > "$work/a.pub"
wg genkey > "$work/b.key"; wg pubkey < "$work/b.key" > "$work/b.pub"
ip -n "$a" link add wg0 type wireguard
ip -n "$b" link add wg0 type wireguard
ip netns exec "$a" wg set wg0 private-key "$work/a.key" listen-port 51871 \
  peer "$(cat "$work/b.pub")" allowed-ips 10.200.250.2/32,fd42:13::2/128 \
  endpoint 198.18.0.6:51872 persistent-keepalive 1
ip netns exec "$b" wg set wg0 private-key "$work/b.key" listen-port 51872 \
  peer "$(cat "$work/a.pub")" allowed-ips 10.200.250.1/32,fd42:13::1/128 \
  endpoint 198.18.0.2:51871 persistent-keepalive 1
ip -n "$a" addr add 10.200.250.1/32 dev wg0
ip -n "$b" addr add 10.200.250.2/32 dev wg0
ip -n "$a" -6 addr add fd42:13::1/128 dev wg0
ip -n "$b" -6 addr add fd42:13::2/128 dev wg0
ip -n "$a" link set wg0 up
ip -n "$b" link set wg0 up
ip -n "$a" route add 10.200.250.2/32 dev wg0
ip -n "$b" route add 10.200.250.1/32 dev wg0
ip -n "$a" -6 route add fd42:13::2/128 dev wg0
ip -n "$b" -6 route add fd42:13::1/128 dev wg0

# Capture genuine underlay packets at the middle namespace. No upload.
ip netns exec "$m" tcpdump -n -U -i opg13-ma -s 160 \
  -w "$work/underlay.pcap" '(ip or ip6)' > "$work/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 2
kill -0 "$capture_pid"

ip netns exec "$a" ping -n -c 3 -W 2 10.200.250.2 > /dev/null
ip netns exec "$b" ping -n -c 2 -W 2 10.200.250.1 > /dev/null
ip netns exec "$a" ping -n -6 -c 3 -W 2 fd42:13::2 > /dev/null
ip netns exec "$b" ping -n -6 -c 2 -W 2 fd42:13::1 > /dev/null

# This is a real UDP/53 DNS wire-message exchange inside wg0, not a system
# resolver change or an external Internet DNS lookup.
ip netns exec "$b" python3 -u "$(dirname "$0")/dns_probe.py" serve > "$work/dns.log" 2>&1 &
dns_pid=$!
sleep 1
kill -0 "$dns_pid"
ip netns exec "$a" python3 "$(dirname "$0")/dns_probe.py" query
wait "$dns_pid"; dns_pid=''

for ns in "$a" "$b"; do
  ip netns exec "$ns" wg show wg0 latest-handshakes | awk 'NF==2 && $2>0 {ok=1} END {exit !ok}'
  ip netns exec "$ns" wg show wg0 transfer | awk 'NF==3 && $2>0 && $3>0 {ok=1} END {exit !ok}'
done

# Simulate an outer-network outage INSIDE the disposable middle namespace.
# Tunnel-scoped inner IPv4 and IPv6 routes must not fall back to the veth.
ip -n "$m" link set opg13-ma down
if ip netns exec "$a" ping -n -c 1 -W 2 10.200.250.2 > /dev/null 2>&1; then
  echo 'Unexpected IPv4 tunnel success with outer path down' >&2; exit 1
fi
if ip netns exec "$a" ping -n -6 -c 1 -W 2 fd42:13::2 > /dev/null 2>&1; then
  echo 'Unexpected IPv6 tunnel success with outer path down' >&2; exit 1
fi
ip -n "$a" route get 10.200.250.2 | grep -q 'dev wg0'
ip -n "$a" -6 route get fd42:13::2 | grep -q 'dev wg0'
ip -n "$m" link set opg13-ma up
ip netns exec "$a" ping -n -c 3 -W 2 10.200.250.2 > /dev/null
ip netns exec "$a" ping -n -6 -c 3 -W 2 fd42:13::2 > /dev/null

kill -INT "$capture_pid" 2>/dev/null || :
wait "$capture_pid" 2>/dev/null || :
capture_pid=''
# Middle network observed UDP encapsulation; no naked inner IPv4/IPv6 or
# DNS/53 traffic. This is not proof of a Windows kill switch.
outer_count=$(tcpdump -n -r "$work/underlay.pcap" \
  '(udp port 51871 or udp port 51872)' 2>/dev/null | wc -l)
if (( outer_count < 4 )); then echo "Insufficient underlay UDP: $outer_count" >&2; exit 1; fi
leaked=$(tcpdump -n -r "$work/underlay.pcap" \
  'net 10.200.250.0/24 or net fd42:13::/64 or port 53' 2>/dev/null | wc -l)
if (( leaked != 0 )); then echo "Plaintext synthetic tunnel/DNS on underlay: $leaked" >&2; exit 1; fi
printf 'G13_PASS: Linux netns A -> middle -> B real WireGuard encrypted IPv4/IPv6; synthetic DNS A+AAAA over tunnel; underlay UDP=%s plaintext=%s; outage/recovery exercised. NOT cross-host/WFP/UU proof.\n' "$outer_count" "$leaked"
