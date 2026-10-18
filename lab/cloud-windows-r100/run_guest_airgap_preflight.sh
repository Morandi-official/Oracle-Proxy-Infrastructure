#!/usr/bin/env bash
# R100 isolated Linux guest NIC foundation; no Windows guest/network egress.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
  "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
  "${GITHUB_EVENT_NAME:-}" != pull_request ||
  "${GITHUB_REPOSITORY:-}" != Morandi-official/Oracle-Proxy-Infrastructure ]]; then
  echo R100_REFUSED_UNTRUSTED_HOST; exit 4
fi
python3 - "$GITHUB_EVENT_PATH" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]))
assert v["repository"]["full_name"]=="Morandi-official/Oracle-Proxy-Infrastructure"
assert v["repository"]["private"] is False
assert v["repository"]["visibility"]=="public"
assert v["pull_request"]["head"]["repo"]["full_name"]==v["repository"]["full_name"]
assert v["pull_request"]["head"]["ref"]=="test/r100-linux-tap-airgap-preflight-20261018"
PY
ns="orpx-r100-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:-1}"
[[ "$ns" =~ ^orpx-r100-[0-9]+-[0-9]+$ ]] || exit 4
pcap="${RUNNER_TEMP:?}/r100-passive-tap.pcap"
created=false
cleanup() {
  set +e
  if $created; then sudo -n ip netns del "$ns"; fi
  rm -f -- "$pcap"
}
trap cleanup EXIT INT TERM
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends iproute2 iputils-ping tcpdump >/dev/null
if sudo -n ip netns list | grep -Fqx "$ns"; then
  echo R100_REFUSED_FOREIGN_EXISTING_NAMESPACE; exit 4
fi
sudo -n ip netns add "$ns"
created=true
sudo -n ip -n "$ns" tuntap add dev tap0 mode tap user "$(id -un)"
sudo -n ip -n "$ns" addr add 198.18.100.1/30 dev tap0
sudo -n ip -n "$ns" link set dev lo up
sudo -n ip -n "$ns" link set dev tap0 up
mapfile -t links < <(sudo -n ip -n "$ns" -o link show | sed -E 's/^[0-9]+: ([^:@]+).*$/\1/' | sort -u)
if (( ${#links[@]} != 2 )) || [[ "${links[0]}" != lo || "${links[1]}" != tap0 ]]; then
  echo R100_FAIL_FOREIGN_OR_MISSING_LINK; exit 5
fi
if [[ -n "$(sudo -n ip -n "$ns" -4 route show default)" ||
      -n "$(sudo -n ip -n "$ns" -6 route show default)" ]]; then
  echo R100_FAIL_DEFAULT_ROUTE; exit 5
fi
if sudo -n ip -n "$ns" -4 route get 1.1.1.1 >/dev/null 2>&1 ||
   sudo -n ip -n "$ns" -6 route get 2606:4700:4700::1111 >/dev/null 2>&1; then
  echo R100_FAIL_EXTERNAL_EGRESS_ROUTE; exit 5
fi
echo R100_LINUX_NETNS_NO_EXTERNAL_IPV4_IPV6_UPLINK_PASS
sudo -n ip netns exec "$ns" timeout 7 tcpdump -i tap0 -n -c 1 -w "$pcap" arp >/dev/null 2>&1 &
cap_pid=$!
sleep 1
sudo -n ip netns exec "$ns" ping -c 1 -W 1 198.18.100.2 >/dev/null 2>&1 || :
wait "$cap_pid" || { echo R100_FAIL_NO_INDEPENDENT_TAP_CAPTURE; exit 5; }
if [[ ! -s "$pcap" ]] || (( $(stat -c %s "$pcap") < 40 )); then
  echo R100_FAIL_EMPTY_CAPTURE; exit 5
fi
echo R100_PASSIVE_HOST_TAP_PACKET_OBSERVER_PASS
sudo -n ip netns del "$ns"
created=false
rm -f -- "$pcap"
if sudo -n ip netns list | grep -Fqx "$ns"; then
  echo R100_FAIL_OWNED_NAMESPACE_RESIDUAL; exit 5
fi
echo R100_EXACT_VIRTUAL_NETWORK_CLEANUP_PASS
echo R100_WINDOWS_VM_NIC_CONNECTED=false
echo R100_VPN_WFP_DRIVER_TESTED=false
echo R100_PUBLIC_NETWORK_ACCESS=false
echo R100_GA_APPROVAL=false
