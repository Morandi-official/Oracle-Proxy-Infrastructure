#!/usr/bin/env bash
set -euo pipefail
umask 077

test "$(id -u)" -eq 0
tools_dir=$(realpath "${1:?upstream binary directory required}")
source_dir=$(dirname "$(realpath "$0")")
policy_program=$(realpath "$source_dir/../../../server/admin-oracle/control/tailscale_egress.py")
python3 "$source_dir/check-admission-reuse.py"
lab_dir=$(mktemp -d /tmp/proxy-ts.XXXXXX)
bridge="pts$$"
readonly coordinator=https://headscale.test
declare -A namespaces
declare -A node_pids
declare -a children

cleanup() {
    status=$?
    if ((status != 0)); then
        printf 'Lab failed at stage %s\n' "${stage:-setup}" >&2
        # Logs can contain registration URLs. Keep CI output limited to markers.
        for name in exit admitted denied replay; do
            if [[ -S "$lab_dir/$name.sock" ]]; then
                "$tools_dir/tailscale" --socket "$lab_dir/$name.sock" status --json 2>/dev/null |
                    jq -c '{BackendState, HaveNodeKey, ExitNodeStatus, Health,
                        Self: (.Self | {TailscaleIPs, Addrs, Relay}),
                        Peer: [.Peer[]? | {HostName, TailscaleIPs, PrimaryRoutes, CurAddr, Relay, TxBytes, RxBytes}]}' || true
            fi
        done
        if [[ ${namespaces[admitted]+yes} == yes ]]; then
            ip -n "${namespaces[admitted]}" route get 198.18.47.2 || true
            ip -n "${namespaces[admitted]}" -6 route get 2001:db8:47::2 || true
        fi
        if [[ ${namespaces[exit]+yes} == yes ]]; then
            ip -n "${namespaces[exit]}" route show || true
            ip netns exec "${namespaces[exit]}" iptables -vnL FORWARD || true
            ip netns exec "${namespaces[exit]}" iptables -vnL ts-forward || true
            ip netns exec "${namespaces[exit]}" iptables -t nat -vnL ts-postrouting || true
        fi
        if [[ -f "$lab_dir/forwarding.log" ]]; then
            tail -n 20 "$lab_dir/forwarding.log"
        fi
    fi
    for child in "${children[@]}"; do
        kill "$child" 2>/dev/null || true
    done
    for namespace in "${namespaces[@]}"; do
        ip netns delete "$namespace" 2>/dev/null || true
        if [[ -f "/etc/netns/$namespace/hosts" ]]; then
            rm -f -- "/etc/netns/$namespace/hosts"
            rmdir -- "/etc/netns/$namespace"
        fi
    done
    ip link delete "$bridge" 2>/dev/null || true
    rm -rf -- "$lab_dir"
}
trap cleanup EXIT

create_namespace() {
    local role=$1
    local namespace="$bridge-$role"
    ip netns add "$namespace"
    namespaces[$role]=$namespace
    ip -n "$namespace" link set lo up
}

configure_test_dns() {
    local directory="/etc/netns/${namespaces[$1]}"
    mkdir -- "$directory"
    printf '127.0.0.1 localhost\n192.0.2.1 headscale.test\n' > "$directory/hosts"
}

attach_peer() {
    local role=$1 address=$2
    local uplink="${bridge}${role:0:2}"
    local namespace="${namespaces[$role]}"
    ip link add "$uplink" type veth peer name "${uplink}p"
    ip link set "${uplink}p" netns "$namespace"
    ip link set "$uplink" netns "${namespaces[lan]}"
    ip -n "${namespaces[lan]}" link set "$uplink" master "$bridge"
    ip -n "${namespaces[lan]}" link set "$uplink" up
    ip -n "$namespace" link set "${uplink}p" name uplink
    ip -n "$namespace" addr add "$address/24" dev uplink
    ip -n "$namespace" link set uplink up
}

create_namespace lan
ip -n "${namespaces[lan]}" link add "$bridge" type bridge
ip -n "${namespaces[lan]}" addr add 192.0.2.1/24 dev "$bridge"
ip -n "${namespaces[lan]}" link set "$bridge" up
create_namespace exit
create_namespace admitted
create_namespace denied
create_namespace replay
create_namespace origin
mkdir -p -- /etc/netns
attach_peer exit 192.0.2.11
attach_peer admitted 192.0.2.12
attach_peer denied 192.0.2.13
attach_peer replay 192.0.2.14
for role in exit admitted denied replay; do
    configure_test_dns "$role"
done
stage=private-link
ip netns exec "${namespaces[admitted]}" ping -q -c 1 -W 2 192.0.2.11 > /dev/null
ip link add "${bridge}wan" type veth peer name "${bridge}web"
ip link set "${bridge}wan" netns "${namespaces[exit]}"
ip link set "${bridge}web" netns "${namespaces[origin]}"
ip -n "${namespaces[exit]}" addr add 198.18.46.1/24 dev "${bridge}wan"
ip -n "${namespaces[exit]}" -6 addr add 2001:db8:46::1/64 dev "${bridge}wan" nodad
ip -n "${namespaces[origin]}" addr add 198.18.46.2/24 dev "${bridge}web"
ip -n "${namespaces[origin]}" -6 addr add 2001:db8:46::2/64 dev "${bridge}web" nodad
ip -n "${namespaces[exit]}" link set "${bridge}wan" up
ip -n "${namespaces[origin]}" link set "${bridge}web" up
# Model an Internet destination beyond the exit's directly connected subnet.
# Tailscale deliberately excludes locally attached networks from exit routes.
ip -n "${namespaces[origin]}" addr add 198.18.47.2/32 dev lo
ip -n "${namespaces[origin]}" -6 addr add 2001:db8:47::2/128 dev lo nodad
ip -n "${namespaces[exit]}" route add 198.18.47.2/32 via 198.18.46.2
ip -n "${namespaces[exit]}" -6 route add 2001:db8:47::2/128 via 2001:db8:46::2
ip netns exec "${namespaces[exit]}" sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

ip netns exec "${namespaces[origin]}" python3 "$source_dir/origin.py" &
children+=("$!")

stage=fixture-tls
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -subj '/CN=Proxy test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -keyout "$lab_dir/ca.key" -out "$lab_dir/ca.pem" \
    > "$lab_dir/openssl.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=headscale.test' \
    -keyout "$lab_dir/headscale-tls.key" -out "$lab_dir/headscale.csr" >> "$lab_dir/openssl.log" 2>&1
printf '%s\n' 'subjectAltName=DNS:headscale.test' 'extendedKeyUsage=serverAuth' > "$lab_dir/leaf.ext"
openssl x509 -req -days 1 -in "$lab_dir/headscale.csr" -CA "$lab_dir/ca.pem" -CAkey "$lab_dir/ca.key" \
    -CAcreateserial -extfile "$lab_dir/leaf.ext" -out "$lab_dir/headscale.pem" >> "$lab_dir/openssl.log" 2>&1

cat > "$lab_dir/derp.yaml" <<'EOF'
regions:
  901:
    regionid: 901
    regioncode: test
    regionname: Isolated test
    nodes:
      - name: test
        regionid: 901
        hostname: derp.invalid
        ipv4: 192.0.2.1
        ipv6: none
        stunport: 3478
        stunonly: true
EOF
cat > "$lab_dir/policy.json" <<'EOF'
{
  "tagOwners": {"tag:oracle-exit": []},
  "autoApprovers": {"exitNode": ["tag:oracle-exit"]},
  "nodeAttrs": [{"target": ["admitted@"], "attr": ["cache-network-maps"]}],
  "grants": [
    {"src": ["admitted@"], "dst": ["autogroup:internet", "198.18.47.2/32", "2001:db8:47::2/128"], "ip": ["*"]}
  ]
}
EOF
cat > "$lab_dir/headscale.yaml" <<EOF
server_url: $coordinator
listen_addr: 192.0.2.1:443
tls_cert_path: $lab_dir/headscale.pem
tls_key_path: $lab_dir/headscale-tls.key
metrics_listen_addr: ""
grpc_listen_addr: 127.0.0.1:50443
unix_socket: $lab_dir/headscale.sock
unix_socket_permission: "0600"
disable_check_updates: true
noise:
  private_key_path: $lab_dir/noise.key
prefixes:
  v4: 100.100.46.0/24
  v6: fd7a:115c:a1e0:46::/64
database:
  type: sqlite
  sqlite:
    path: $lab_dir/db.sqlite
policy:
  mode: file
  path: $lab_dir/policy.json
derp:
  server:
    enabled: false
  urls: []
  paths: [$lab_dir/derp.yaml]
  auto_update_enabled: false
dns:
  magic_dns: false
  override_local_dns: false
  nameservers:
    global: []
    split: {}
EOF

headscale() {
    "$tools_dir/headscale" --config "$lab_dir/headscale.yaml" "$@"
}

headscale_admission() {
    python3 "$source_dir/check-control.py" "$tools_dir/headscale" "$lab_dir/headscale.yaml" "$lab_dir/proxy-devices.sqlite" "$@"
}

tailscale() {
    local role=$1
    shift
    ip netns exec "${namespaces[$role]}" "$tools_dir/tailscale" --socket "$lab_dir/$role.sock" "$@"
}

daemon_api() {
    local role=$1 method=$2 endpoint=$3
    curl --unix-socket "$lab_dir/$role.sock" --noproxy '*' --fail --silent --show-error \
        --max-time 5 --request "$method" --header 'Content-Type: application/json' --data-binary @- \
        "http://local-tailscaled.sock/localapi/v0/$endpoint"
}

login_via_daemon() {
    local role=$1 key_file=$2
    jq -n --arg coordinator "$coordinator" --rawfile key "$key_file" '{
        AuthKey: ($key | rtrimstr("\n")),
        UpdatePrefs: {
            ControlURL: $coordinator,
            WantRunning: true, ShieldsUp: true, CorpDNS: true, RouteAll: false
        }
    }' | daemon_api "$role" POST start > "$lab_dir/$role.login.log"
    daemon_api "$role" POST login-interactive </dev/null >> "$lab_dir/$role.login.log"
    for _ in {1..30}; do
        if tailscale "$role" status --json | jq -e '.BackendState == "Running" and .HaveNodeKey' >/dev/null; then
            return
        fi
        sleep 0.5
    done
    return 1
}

start_node() {
    local role=$1
    mkdir -p -- "$lab_dir/$role"
    ip netns exec "${namespaces[$role]}" env TS_NO_LOGS_NO_SUPPORT=true TS_USE_CACHED_NETMAP="${2:-true}" \
        DBUS_SYSTEM_BUS_ADDRESS="unix:path=$lab_dir/no-system-dbus" \
        SSL_CERT_FILE="$lab_dir/ca.pem" \
        "$tools_dir/tailscaled" --state "$lab_dir/$role.state" --socket "$lab_dir/$role.sock" \
        --statedir "$lab_dir/$role" --tun tailscale0 --port 41641 > "$lab_dir/$role.log" 2>&1 &
    node_pids[$role]=$!
    children+=("${node_pids[$role]}")
    for _ in {1..50}; do
        if [[ -S "$lab_dir/$role.sock" ]]; then return; fi
        sleep 0.1
    done
    return 1
}

stop_admitted() {
    printf '%s\n' '{"WantRunning":false,"WantRunningSet":true}' | daemon_api admitted PATCH prefs >/dev/null
    kill -TERM "${node_pids[admitted]}"
    wait "${node_pids[admitted]}"
    test ! -S "$lab_dir/admitted.sock"
}

login() {
    local role=$1 key_file=$2
    shift 2
    tailscale "$role" up --login-server "$coordinator" --auth-key "file:$key_file" \
        --accept-dns=false --accept-routes=false --hostname "$role" --timeout 15s "$@" \
        > "$lab_dir/$role.login.log" 2>&1
}

http_origin() {
    local role=$1 family=$2
    local url=http://198.18.47.2:8081/
    if [[ "$family" == 6 ]]; then url=http://[2001:db8:47::2]:8081/; fi
    ip netns exec "${namespaces[$role]}" curl --noproxy '*' --silent --fail \
        --connect-timeout 1 --max-time 2 "$url"
}

wait_for_origin() {
    local family=$1 expected=$2
    for _ in {1..12}; do
        if [[ "$(http_origin admitted "$family")" = "$expected" ]]; then return; fi
        sleep 0.5
    done
    return 1
}

apply_lease_policy() {
    ip netns exec "${namespaces[exit]}" python3 "$policy_program" "$@"
}

origin_blocked() {
    ! http_origin "$1" 4 && ! http_origin "$1" 6
}

measure_path() {
    local phase=$1 url=http://198.18.47.2:8081
    local samples="$lab_dir/$phase.rtt" rates="$lab_dir/$phase.rates"
    local -a request=(ip netns exec "${namespaces[admitted]}" curl --noproxy '*' --silent --fail
        --connect-timeout 1 --max-time 4 --output /dev/null)
    for _ in {1..20}; do
        "${request[@]}" --write-out '%{time_connect}\n' "$url/" >> "$samples"
    done
    for _ in {1..3}; do
        "${request[@]}" --write-out '%{speed_download} ' "$url/throughput" >> "$rates"
        "${request[@]}" --header 'Expect:' --upload-file "$lab_dir/upload" \
            --write-out '%{speed_upload}\n' "$url/throughput" >> "$rates"
    done
    python3 - "$phase" "$samples" "$rates" <<'PY'
import json
import math
import statistics
import sys

phase, samples_path, rates_path = sys.argv[1:]
with open(samples_path) as values:
    rtt = sorted(float(value) * 1000 for value in values)
with open(rates_path) as values:
    download, upload = zip(*(tuple(float(rate) * 8 / 1_000_000 for rate in line.split()) for line in values))
print("TAILSCALE_LAB_PERFORMANCE=" + json.dumps({
    "path": phase, "down_mbps_median": round(statistics.median(download), 1),
    "up_mbps_median": round(statistics.median(upload), 1),
    "tcp_connect_ms_p50": round(statistics.median(rtt), 3),
    "tcp_connect_ms_p95": round(rtt[math.ceil(len(rtt) * .95) - 1], 3),
}))
PY
}

select_exit() {
    jq -n --arg id "$1" '{
        ExitNodeID:$id, ExitNodeIDSet:true, ExitNodeIPSet:true,
        ExitNodeAllowLANAccess:false, ExitNodeAllowLANAccessSet:true,
        WantRunning:true, WantRunningSet:true
    }' | daemon_api admitted PATCH prefs > /dev/null
}

stage=headscale-startup
ip netns exec "${namespaces[lan]}" "$tools_dir/headscale" --config "$lab_dir/headscale.yaml" \
    serve > "$lab_dir/headscale.log" 2>&1 &
children+=("$!")
for _ in {1..60}; do
    if [[ -S "$lab_dir/headscale.sock" ]] && headscale users list -o json > /dev/null 2>&1; then break; fi
    sleep 0.2
done
headscale users list -o json > /dev/null
admitted=$(headscale users create admitted -o json | jq -er '.id')
denied=$(headscale users create denied -o json | jq -er '.id')
headscale preauthkeys create --tags tag:oracle-exit --expiration 5m > "$lab_dir/exit.key"
headscale_admission issue "$admitted" > "$lab_dir/admitted.key"
headscale_admission absent "$admitted"
headscale_admission pending "$admitted"
headscale preauthkeys create --user "$denied" --expiration 5m > "$lab_dir/denied.key"

stage=start-nodes
start_node exit
start_node admitted
start_node denied
start_node replay
stage=register-exit
login exit "$lab_dir/exit.key" --advertise-exit-node
stage=register-authorized-device
login_via_daemon admitted "$lab_dir/admitted.key"
echo 'TAILSCALE_CLIENT_LOCAL_API_ENROLLMENT=PASS'
stage=register-unauthorized-device
login denied "$lab_dir/denied.key"
stage=reject-replayed-registration
if login replay "$lab_dir/admitted.key"; then
    echo 'A second node reused a consumed enrollment key' >&2
    exit 1
fi
test "$(headscale nodes list --user admitted -o json | jq 'length')" = 1
headscale_admission deny-owner "$denied" --username denied
echo 'TAILSCALE_SINGLE_USE_ADMISSION=PASS'

stage=origin-reachable-from-exit
test "$(http_origin exit 4)" = 198.18.46.1
test "$(http_origin exit 6)" = 2001:db8:46::1

stage=direct-baseline
truncate -s 64M "$lab_dir/upload"
ip -n "${namespaces[admitted]}" route add 198.18.47.2/32 via 192.0.2.11
ip -n "${namespaces[origin]}" route add 192.0.2.12/32 via 198.18.46.1
measure_path direct_baseline
ip -n "${namespaces[admitted]}" route del 198.18.47.2/32 via 192.0.2.11

stage=entry-route
if http_origin admitted 4 || http_origin admitted 6; then
    echo 'Origin reachable before selecting an exit node' >&2
    exit 1
fi
exit_ipv4=$(tailscale exit ip -4)
exit_node=$(tailscale exit status --json | jq -er '.Self.ID')
select_exit "$exit_node"
if command -v tcpdump >/dev/null; then
    ip netns exec "${namespaces[exit]}" timeout 28 tcpdump -nnl -i any -s 96 \
        'tcp port 8081 and (host 198.18.47.2 or host 2001:db8:47::2)' \
        > "$lab_dir/forwarding.log" 2>&1 &
    children+=("$!")
fi
stage=isolated-ipv4-egress
wait_for_origin 4 198.18.46.1
stage=isolated-ipv6-egress
wait_for_origin 6 2001:db8:46::1
stage=direct-wireguard-peer
ip netns exec "${namespaces[exit]}" env PYTHONPATH="$(dirname "$policy_program")" python3 - "$lab_dir/exit.sock" "$exit_node" <<'PY'
import sys
from tailscale_gateway import read_exit_status

socket_path, node_id = sys.argv[1:]
status = read_exit_status(socket_path)
assert status['BackendState'] == 'Running' and status['Self']['ID'] == node_id
PY
tailscale admitted status --json |
    jq -e --arg remote "$exit_ipv4" '.Peer[] | select(.TailscaleIPs | index($remote)) | .Active and ((.CurAddr // "") | startswith("192.0.2.11:"))' > /dev/null
echo 'TAILSCALE_DIRECT_WIREGUARD_EXIT_IPV4_IPV6=PASS'

stage=udp-dns-egress
test "$(ip netns exec "${namespaces[admitted]}" dig +tries=1 +time=2 +short @198.18.47.2 egress.test A)" = 198.18.47.2
echo 'TAILSCALE_UDP_DNS_THROUGH_EXIT=PASS'

stage=unauthorized-and-revoked-egress
tailscale denied set --exit-node "$exit_ipv4" >/dev/null 2>&1 || true
if ! origin_blocked denied; then
    echo 'Unauthorized node used the exit' >&2
    exit 1
fi
echo 'TAILSCALE_UNAUTHORIZED_DEVICE_DENIED=PASS'

stage=fail-closed-forwarding-lease
apply_lease_policy install
origin_blocked admitted
bound=$(headscale_admission find "$admitted")
read -r admitted_ipv4 admitted_ipv6 <<< "$bound"
test "$admitted_ipv4" = "$(tailscale admitted ip -4)"
test "$admitted_ipv6" = "$(tailscale admitted ip -6)"
echo 'TAILSCALE_TICKET_BOUND_TO_COORDINATOR_NODE=PASS'
tailscale exit status --json | headscale_admission traffic "$admitted"
echo 'TAILSCALE_ACCOUNT_NODE_TRAFFIC_COUNTERS=PASS'
apply_lease_policy replace "$admitted_ipv4" "$admitted_ipv6"
wait_for_origin 4 198.18.46.1
wait_for_origin 6 2001:db8:46::1
stage=tunnel-performance
measure_path wireguard_direct
for _ in {1..5}; do
    select_exit ''
    start_ms=$(date +%s%3N)
    select_exit "$exit_node"
    for _ in {1..20}; do
        if [[ "$(http_origin admitted 4)" == 198.18.46.1 && "$(http_origin admitted 6)" == 2001:db8:46::1 ]]; then
            printf 'TAILSCALE_LAB_RESELECT_VERIFIED_MS=%s\n' "$(( $(date +%s%3N) - start_ms ))"
            break
        fi
        sleep .1
    done
    test "$(http_origin admitted 4)" = 198.18.46.1
    test "$(http_origin admitted 6)" = 2001:db8:46::1
    apply_lease_policy replace "$admitted_ipv4" "$admitted_ipv6"
done
stage=rate-policy
ip netns exec "${namespaces[exit]}" env PYTHONPATH="$(dirname "$policy_program")" python3 - "$admitted_ipv4" "$admitted_ipv6" <<'PY'
import sys
from tailscale_egress import apply_rules, rate_rules, rate_table_exists

assert not rate_table_exists()
apply_rules(rate_rules(((1, 100_000_000, 50_000_000, tuple(sys.argv[1:])),), False))
assert rate_table_exists()
apply_rules(rate_rules((), True))
assert not rate_table_exists()
PY
stage=fail-closed-forwarding-lease
apply_lease_policy replace --seconds 2 "$admitted_ipv4" "$admitted_ipv6"
sleep 3
origin_blocked admitted
echo 'TAILSCALE_BOTH_FAMILIES_FAIL_CLOSED_ON_LEASE_EXPIRY=PASS'

stage=cached-map-after-clean-stop
stop_admitted
# Hold only the isolated client's coordination channel. The exit, carrier and
# origin remain reachable, and the dedicated forwarding lease still gates data.
ip netns exec "${namespaces[admitted]}" iptables -I OUTPUT -d 192.0.2.1 -p tcp --dport 443 -j REJECT
start_node admitted false
select_exit "$exit_node"
apply_lease_policy replace "$admitted_ipv4" "$admitted_ipv6"
origin_blocked admitted
tailscale admitted status --json | jq -e '.ExitNodeStatus == null' >/dev/null
stop_admitted

start_node admitted
apply_lease_policy replace "$admitted_ipv4" "$admitted_ipv6"
start_ms=$(date +%s%3N)
select_exit "$exit_node"
for _ in {1..30}; do
    if tailscale admitted status --json | jq -e --arg exit "$exit_node" \
        '.BackendState == "Running" and .ExitNodeStatus.ID == $exit' >/dev/null; then
        break
    fi
    sleep 0.05
done
tailscale admitted status --json | jq -e --arg exit "$exit_node" \
    '.BackendState == "Running" and .ExitNodeStatus.ID == $exit' >/dev/null
printf 'TAILSCALE_LAB_CACHED_ROUTE_MS=%s\n' "$(( $(date +%s%3N) - start_ms ))"
# A restart can rotate discovery state. Validate traffic after the exit has
# received current peer data, even when the mapped route appeared earlier.
ip netns exec "${namespaces[admitted]}" iptables -D OUTPUT -d 192.0.2.1 -p tcp --dport 443 -j REJECT
wait_for_origin 4 198.18.46.1
wait_for_origin 6 2001:db8:46::1
printf 'TAILSCALE_LAB_CACHED_RESTART_VERIFIED_MS=%s\n' "$(( $(date +%s%3N) - start_ms ))"
apply_lease_policy replace --seconds 2 "$admitted_ipv4" "$admitted_ipv6"
sleep 3
origin_blocked admitted
echo 'TAILSCALE_CACHED_MAP_OBEYS_FORWARD_LEASE=PASS'

stage=revoked-node
apply_lease_policy replace "$admitted_ipv4" "$admitted_ipv6"
wait_for_origin 4 198.18.46.1
wait_for_origin 6 2001:db8:46::1
headscale_admission revoke "$admitted"
headscale_admission revoke "$admitted"
headscale_admission absent "$admitted"
for _ in {1..3}; do
    if origin_blocked admitted; then
        echo 'TAILSCALE_REVOKED_DEVICE_EGRESS_STOPPED=PASS'
        exit 0
    fi
    sleep 1
done
echo 'Revoked device retained egress' >&2
exit 1
