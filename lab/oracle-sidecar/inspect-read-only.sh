#!/usr/bin/env bash
# R9: existing Oracle Linux host sidecar READ-ONLY PRE-FLIGHT.
# No route, config, key, firewall, service, OS or cloud-ingress mutation.
set -euo pipefail

self_test() {
  for port in 52911 52912 52913; do
    [[ "$port" =~ ^[0-9]{5}$ ]] && (( port > 49152 && port < 65535 )) || exit 1
  done
  printf 'R9_SELF_TEST_PASS: no writes, no credentials, lab port bounds valid\n'
}
if [[ "$#" == 1 && "$1" == "--self-test" ]]; then self_test; exit 0; fi
if [[ "$#" != 0 ]]; then
  printf 'R9_REFUSED: no arguments accepted, apart from --self-test\n' >&2
  exit 4
fi
if [[ "$(uname -s)" != Linux ]]; then
  printf 'R9_REFUSED: Linux inspection only\n' >&2
  exit 4
fi

printf 'schema_version=1\n'
printf 'mode=read_only_existing_oracle_sidecar_preflight\n'
printf 'linux_kernel_family=Linux\n'
printf 'linux_arch=%s\n' "$(uname -m)"
if command -v wg >/dev/null 2>&1; then
  printf 'wireguard_cli=present\n'
else
  printf 'wireguard_cli=not_found\n'
fi
if command -v ip >/dev/null 2>&1; then
  if ip link show dev wg0 >/dev/null 2>&1; then
    printf 'existing_wg0=present_do_not_modify\n'
  else
    printf 'existing_wg0=not_found_or_not_accessible\n'
  fi
else
  printf 'existing_wg0=unknown_ip_tool_unavailable\n'
fi
if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
  current=$(cat /proc/sys/net/ipv4/ip_forward)
  case "$current" in
    0|1) printf 'observed_ipv4_forwarding=%s\n' "$current";;
    *) printf 'observed_ipv4_forwarding=unknown\n';;
  esac
else
  printf 'observed_ipv4_forwarding=unknown\n'
fi
if command -v ss >/dev/null 2>&1; then
  # Addresses are NEVER printed: only possible test-port occupancy.
  listeners="$(ss -H -lun 2>/dev/null || :)"
  for port in 52911 52912 52913; do
    if printf '%s\n' "$listeners" | awk -v port="$port" '{
        if ($5 ~ ":" port "$") used=1
      } END {exit !used}'; then
      printf 'candidate_udp_%s=already_listening\n' "$port"
    else
      printf 'candidate_udp_%s=no_local_listener_detected\n' "$port"
    fi
  done
else
  for port in 52911 52912 52913; do
    printf 'candidate_udp_%s=unknown_ss_unavailable\n' "$port"
  done
fi
printf 'cloud_security_ingress=NOT_VERIFIED\n'
printf 'out_of_band_console_and_snapshot=NOT_VERIFIED\n'
printf 'safe_to_enable_oracle_sidecar=false\n'
printf 'production_wireguard_modified=false\n'
printf 'route_dns_firewall_modified=false\n'
printf 'keys_or_endpoints_collected=false\n'
printf 'R9_READ_ONLY_DONE: review before explicit operator change approval\n'
