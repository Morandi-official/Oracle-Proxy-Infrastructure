# Source after constructing the existing pinned SSH array without its destination.
# Only read-only probes may repeat; callers execute their mutation exactly once.
select_proxy_ssh_endpoint() {
  local proxy_user="$1" proxy_probe="$2" proxy_candidate
  shift 2
  case "$proxy_user:$proxy_probe" in
    oracle-ci:agent-status|oracle-project-ci:logs\ *) ;;
    *) echo 'READ_ONLY_SSH_PROBE_REQUIRED' >&2; return 2 ;;
  esac
  local -a proxy_targets
  mapfile -t proxy_targets < <(python3 ops/network/endpoint_catalog.py --legacy)
  PROXY_SSH_TARGET=''
  for proxy_candidate in "${proxy_targets[@]}"; do
    if "$@" -o ConnectTimeout=3 "$proxy_user@$proxy_candidate" "$proxy_probe" >/dev/null; then
      PROXY_SSH_TARGET="$proxy_user@$proxy_candidate"
      return 0
    fi
  done
  echo 'NO_CONFIGURED_MANAGEMENT_ENDPOINT' >&2
  return 2
}
