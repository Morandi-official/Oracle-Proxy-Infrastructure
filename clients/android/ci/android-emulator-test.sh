#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 || ( $# -eq 4 && "$4" != production && "$4" != port-monitor ) ]]; then
    echo 'Usage: android-emulator-test.sh API app.apk instrumentation.apk [production|port-monitor]' >&2
    exit 2
fi
api="$1"
app="$2"
test_apk="$3"
mode="${4:-isolated}"
image="system-images;android-${api};google_apis;x86_64"
avd="proxy-api-${api}"
working_dir="$(mktemp -d)"
export ANDROID_USER_HOME="$working_dir/android-user"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
emulator_pid=
cleanup() {
    adb emu kill >/dev/null 2>&1 || true
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
        # The emulator can still write AVD state after accepting termination.
        if ! timeout 8 tail --pid="$emulator_pid" -f /dev/null; then
            kill -KILL "$emulator_pid" 2>/dev/null || true
        fi
        wait "$emulator_pid" 2>/dev/null || true
    fi
    if [[ "$mode" == isolated ]]; then
        sudo ip link del wg-proxy-ci 2>/dev/null || true
        if [[ -f "$working_dir/fixture.pid" ]]; then
            sudo kill "$(cat "$working_dir/fixture.pid")" 2>/dev/null || true
        fi
    fi
    rm -rf -- "$working_dir"
}
trap cleanup EXIT

[[ -e /dev/kvm ]] || { echo 'Android acceptance requires KVM on the runner.' >&2; exit 1; }
sudo chmod a+rw /dev/kvm
sdkmanager platform-tools emulator "$image"
printf 'no\n' | avdmanager create avd --force --name "$avd" --package "$image" \
    --path "$ANDROID_AVD_HOME/$avd.avd"
emulator_bin="${ANDROID_HOME:?Android SDK root required}/emulator/emulator"
[[ -x "$emulator_bin" ]] || { echo 'Android emulator executable missing after SDK install.' >&2; exit 1; }
"$emulator_bin" -list-avds | grep -Fxq "$avd"
"$emulator_bin" -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect -accel on \
    >"$working_dir/emulator.log" 2>&1 &
emulator_pid=$!
sleep 2
if ! kill -0 "$emulator_pid" 2>/dev/null; then
    cat "$working_dir/emulator.log"
    exit 1
fi
if ! timeout 180 adb wait-for-device; then
    cat "$working_dir/emulator.log"
    exit 1
fi
if ! timeout 180 bash -c 'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'; then
    cat "$working_dir/emulator.log"
    exit 1
fi
adb shell input keyevent 82
if [[ "$mode" != production ]]; then
    adb shell settings put global window_animation_scale 0
    adb shell settings put global transition_animation_scale 0
    adb shell settings put global animator_duration_scale 0
fi

if [[ "$mode" == production || "$mode" == port-monitor ]]; then
    animation_scale() {
        local scale
        scale=$(adb shell settings get global "$1" | tr -d '\r')
        if [[ "$scale" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            printf '%s' "$scale"
        elif [[ "$scale" == null ]]; then
            printf 'DEFAULT'
        else
            printf 'UNKNOWN'
        fi
    }
    printf 'ANDROID_PERF_VISUAL_ENV=API:%s;WINDOW_SCALE:%s;TRANSITION_SCALE:%s;ANIMATOR_SCALE:%s\n' \
        "$api" "$(animation_scale window_animation_scale)" \
        "$(animation_scale transition_animation_scale)" "$(animation_scale animator_duration_scale)"
    if [[ -z "${ANDROID_ACCEPTANCE_USERNAME:-}" || -z "${ANDROID_ACCEPTANCE_PASSWORD:-}" ]]; then
        echo 'The dedicated client acceptance credentials are required.' >&2
        exit 1
    fi
    user_b64="$(printf '%s' "$ANDROID_ACCEPTANCE_USERNAME" | base64 -w0)"
    pass_b64="$(printf '%s' "$ANDROID_ACCEPTANCE_PASSWORD" | base64 -w0)"
    printf '::add-mask::%s\n' "$user_b64" "$pass_b64"
    unset ANDROID_ACCEPTANCE_USERNAME ANDROID_ACCEPTANCE_PASSWORD
    adb install -t "$app"
    adb install -t "$test_apk"
    adb shell setprop log.tag.ProxyVpnTiming D
    run_production_test() {
        adb shell am instrument -w -e class "org.morandi.proxy.ProductionLifecycleTest#$1" \
            -e proxyProduction 1 -e proxyUser "$user_b64" -e proxyPass "$pass_b64" \
            -e proxyRun "$GITHUB_RUN_ID" org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner \
            | tee "$2"
    }
    if [[ "$mode" == port-monitor ]]; then
        adb shell appops set org.morandi.proxy ACTIVATE_VPN allow
        adb shell am instrument -w -e class org.morandi.proxy.ProductionLifecycleTest#monitorProductionPorts \
            -e proxyPortMonitor 1 -e proxyUser "$user_b64" -e proxyPass "$pass_b64" \
            org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner | tee "$working_dir/port-monitor.txt"
        grep -Eq '^OK \(1 test\)' "$working_dir/port-monitor.txt"
        adb logcat -d -v raw -s ProxyPortMonitor:I '*:S' | grep -Ex 'PORT_MONITOR (443|8443|51820) (success|failure|error)'
        exit 0
    fi
    run_production_test signedAppAgainstProduction "$working_dir/instrumentation.txt"
    # Run the same signed APK with fresh app data and a new process. No saved key,
    # authenticated connection pool or in-process JIT state can carry over from headless password login.
    adb shell pm clear org.morandi.proxy | tr -d '\r' | grep -qx Success
    run_production_test signedForegroundLogin "$working_dir/foreground-login.txt"
    unset user_b64 pass_b64
    # The app times the real Builder.establish() call. The preceding WireGuard
    # marker also identifies time spent in configuration before the OS call.
    # Only numeric timings are emitted from the emulator log.
    adb logcat -d -v epoch 'WireGuard/GoBackend:D' 'ProxyVpnTiming:D' '*:S' | awk '
        /Requesting to start VpnService[[:space:]]*$/ { stock_starts++ }
        /Bringing tunnel Proxy UP[[:space:]]*$/ { started = $1; attempt++ }
        /ProxyVpnTiming: ESTABLISH_NS=[0-9]+[[:space:]]*$/ && started {
            os_ns = $NF
            sub(/^ESTABLISH_NS=/, "", os_ns)
            pre_ms = ($1 - started) * 1000 - os_ns / 1000000
            if (pre_ms < 0) pre_ms = 0
            printf "ANDROID_PERF_NATIVE_OS_ESTABLISH_NS=%.0f;BEFORE_OS_MS=%.0f;ATTEMPT=%d\n", os_ns, pre_ms, attempt
            started = 0
        }
        END { if (attempt) printf "ANDROID_PERF_GO_BACKEND_SERVICE_STARTS=%d;UP_ATTEMPTS=%d\n", stock_starts, attempt }'
    download='^ANDROID_DOWNLOAD_(DIRECT|WIREGUARD_UDP)_BYTES=[0-9]+;ELAPSED_MS=[0-9]+$'
    timing='^ANDROID_PERF_(LOGIN_(FRESH|SAVED_CONTROLLER|WARM|FOREGROUND)_MS=[0-9]+;TARGET_MS=1000|'
    timing+='CONNECT_(FIRST_CLICK|AFTER_CONSENT|RECONNECT_CLICK)_MS=[0-9]+;TARGET_MS=1000);UNDER_TARGET=[01]$'
    reconnect_series='^ANDROID_PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS=([0-9]+,){4}[0-9]+'
    reconnect_series+=';N=5;MEDIAN_MS=[0-9]+;MAX_MS=[0-9]+;UNDER_1000MS=[0-5]$'
    visual='^ANDROID_PERF_VISUAL_DIAGNOSTICS_(FIRST_CLICK|AFTER_CONSENT|RECONNECT_[1-5]|LOGIN_FOREGROUND)='
    visual+='DOWN_CALL_NS:(-1|[0-9]+);UP_CALL_NS:(-1|[0-9]+);APP_DOWN_DELIVERY_NS:(-1|[0-9]+)'
    visual+=';APP_UP_DELIVERY_NS:(-1|[0-9]+);CONSENT_RESULT_NS:(-1|[0-9]+);FOCUS_GAIN_NS:(-1|[0-9]+)'
    visual+=';FIRST_VERIFIED_DRAW_NS:(-1|[0-9]+);FIRST_DRAW_FOCUSED:(-1|[01]);FOCUSED_DRAW_NS:(-1|[0-9]+)$'
    login_phases='^ANDROID_PERF_LOGIN_(FRESH|WARM|FOREGROUND)_PHASES=QUEUE_MS:[0-9]+,IDENTITY_MS:[0-9]+,AUTH_MS:[0-9]+,SESSION_MS:[0-9]+'
    login_phases+=',STREAM_OPEN_MS:[0-9]+,UPLOAD_MS:[0-9]+,RESPONSE_HEADERS_MS:[0-9]+,RESPONSE_BODY_MS:[0-9]+'
    login_phases+=',NETWORK_SELECT_MS:[0-9]+,CONFIGURE_MS:[0-9]+,OUTPUT_OPEN_MS:[0-9]+'
    login_phases+=',WARMUP_AT_START:(NONE|RUNNING|READY|UNAVAILABLE),WARMUP_AT_OUTPUT:(NONE|RUNNING|READY|UNAVAILABLE)$'
    families='^ANDROID_PERF_VERIFIED_FAMILIES=[12]$'
    proof='^ANDROID_PERF_EXIT_PROOF_(FIRST|RECONNECT(_[2-5])?)=IPV4:(h3|https);IPV6:(h3|https|blocked);H3_CANDIDATE=[01]$'
    phases='^ANDROID_PERF_CONNECT_PHASES_(FIRST|RECONNECT(_[2-5])?)=TOTAL_MS:[0-9]+;POLICY_MS:[0-9]+;QUEUE_MS:[0-9]+;PREPARATION_MS:[0-9]+;POLICY_WAIT_MS:[0-9]+;CONSENT_POLICY_AGE_MS:(-1|[0-9]+);BACKEND_WAIT_MS:[0-9]+;SERVICE_WAIT_MS:[0-9]+;SERVICE_REQUEST_MS:[0-9]+;FOREGROUND_ACK_MS:[0-9]+;BASELINE_READ_MS:[0-9]+;RETRIED_SERVICE_START:[01];NATIVE_START_MS:[0-9]+;NETWORK_WAIT_MS:[0-9]+'
    phases+=';NETWORK_DISCOVERY_MS:[0-9]+;NETWORK_OWNER_WAIT_MS:[0-9]+;BIND_READY_MS:[0-9]+;EMPTY_BIND_FAILURES:[0-9]+'
    phases+=';FIRST_BIND_ERRNO:(-1|[0-9]+);LAST_BIND_ERRNO:(-1|[0-9]+);BLOCKED_AT_DISCOVERY:(-1|[01]);BLOCKED_AT_BIND:(-1|[01]);EXIT_PROOF_MS:[0-9]+;WG_HANDSHAKE_MS:(-1|[0-9]+)'
    phases+=';IPV4_PROOF_MS:[0-9]+;IPV4_PROOF_ATTEMPTS:[1-3];IPV6_PROOF_MS:[0-9]+;IPV6_PROOF_ATTEMPTS:[0-3];ATTEMPTS:[0-9]+$'
    latency='^ANDROID_PERF_HTTPS_(DIRECT|WIREGUARD_UDP)_(FRESH|REUSED)_SAMPLES_MS=([0-9]+,){19}[0-9]+'
    latency+=';N=20;MEDIAN_MS=[0-9]+;P95_MS=[0-9]+;UNDER_500MS=[0-9]+;HOST=www[.]cloudflare[.]com'
    latency+=';PATH=/cdn-cgi/trace;ENDPOINT=[0-9.]+;ADDRESS_FAMILY=IPv4;PROTOCOL=HTTP_1_1$'
    rtt_sample='(-1|[0-9]+[.][0-9]{3})'
    rtt="^ANDROID_PERF_UDP_STUN_(DIRECT|WIREGUARD_UDP(_UPLOAD|_DOWNLOAD)?)_RTT_MS=($rtt_sample,){11}$rtt_sample"
    rtt+=';N=12;REPLIES=[0-9]+;UNANSWERED=[0-9]+;PROBE_LOSS_PERCENT=[0-9]+[.][0-9]{3}'
    rtt+=";MEDIAN_MS=$rtt_sample;P95_MS=$rtt_sample;MEAN_ADJACENT_RTT_CHANGE_MS=$rtt_sample"
    rtt+=';HOST=(stun[.]cloudflare[.]com|stun[.]l[.]google[.]com);ENDPOINT=[0-9.]+;PORT=(3478|19302)'
    rtt+=';TIMEOUT_MS=1200;VPN_EXIT_VERIFIED=[01]$'
    rtt_unavailable='^ANDROID_PERF_UDP_STUN_(DIRECT|WIREGUARD_UDP)_STATUS=(DNS_UNAVAILABLE|NO_IPV4_ADDRESS)'
    rtt_unavailable+=';HOST=(stun[.]cloudflare[.]com|stun[.]l[.]google[.]com);PORT=(3478|19302)$'
    load='^ANDROID_PERF_LOAD_(UPLOAD|DOWNLOAD)_RATES_MBPS=([0-9]+[.][0-9]{2},){2,31}[0-9]+[.][0-9]{2}'
    load+=';N=[0-9]+;BYTES_PER_TRANSFER=2097152;RTT_SAMPLES=12;PROBES_WITH_BODY_PROGRESS=[0-9]+$'
    body_progress='^ANDROID_PERF_WIREGUARD_UDP_(UPLOAD|DOWNLOAD)_RTT_BODY_BYTES=([0-9]+,){11}[0-9]+$'
    guest='^ANDROID_PERF_GUEST_LOAD_(UPLOAD|DOWNLOAD)=TUN_MTU=(-1|[0-9]+);NIC_MTU=(-1|[0-9]+)'
    guest+='(;[A-Za-z]+[.][A-Za-z]+=(0|[1-9][0-9]*|-1)){15}$'
    carrier_options='^ANDROID_PERF_CARRIER_SOCKET_V[46]=RCVBUF_BYTES:(-1|[0-9]+);UDP_GRO:(-1|0|1)$'
    carrier='^ANDROID_PERF_CARRIER_(DOWNLOAD|UPLOAD)=V4_SOCKET_DROPS:(-1|[0-9]+);V6_SOCKET_DROPS:(-1|[0-9]+);TUN_TX_PACKETS:(-1|[0-9]+)$'
    upload_control='^ANDROID_PERF_UPLOAD_CONTROL_[12]=SAME_IP:(-1|0|1);SAME_POP:(-1|0|1);SAME_PROTOCOL:(-1|0|1);SAME_CIPHER:(-1|0|1)'
    upload_control+=';VPN_ACK_MS:(-1|[0-9]+);RETRANS:(-1|[0-9]+);SEGS_OUT:(-1|[0-9]+)'
    upload_control+=';DIRECT_ACK_MS:(-1|[0-9]+);RETRANS:(-1|[0-9]+);SEGS_OUT:(-1|[0-9]+)$'
    adb logcat -d -v raw -s ProxySpeedAcceptance:I '*:S' |
        grep -E -e "$download" -e "$timing" -e "$reconnect_series" -e "$visual" -e "$login_phases" -e "$families" -e "$proof" \
            -e "$phases" -e "$latency" -e "$rtt" -e "$rtt_unavailable" -e "$load" -e "$body_progress" -e "$guest" -e "$carrier" -e "$carrier_options" -e "$upload_control" |
        tee "$working_dir/performance.txt"
    grep -Eq '^OK \(1 test\)' "$working_dir/instrumentation.txt"
    grep -Eq '^OK \(1 test\)' "$working_dir/foreground-login.txt"
    for metric in DOWNLOAD_DIRECT_BYTES PERF_LOAD_DOWNLOAD_RATES_MBPS PERF_LOAD_UPLOAD_RATES_MBPS PERF_VERIFIED_FAMILIES \
        PERF_LOGIN_FRESH_MS PERF_LOGIN_SAVED_CONTROLLER_MS PERF_LOGIN_WARM_MS \
        PERF_LOGIN_FRESH_PHASES PERF_LOGIN_WARM_PHASES PERF_LOGIN_FOREGROUND_MS PERF_LOGIN_FOREGROUND_PHASES \
        PERF_CONNECT_FIRST_CLICK_MS PERF_CONNECT_AFTER_CONSENT_MS PERF_CONNECT_RECONNECT_CLICK_MS \
        PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS \
        PERF_VISUAL_DIAGNOSTICS_FIRST_CLICK PERF_VISUAL_DIAGNOSTICS_AFTER_CONSENT \
        PERF_EXIT_PROOF_FIRST PERF_EXIT_PROOF_RECONNECT \
        PERF_CONNECT_PHASES_FIRST PERF_CONNECT_PHASES_RECONNECT \
        PERF_HTTPS_DIRECT_FRESH_SAMPLES_MS PERF_HTTPS_DIRECT_REUSED_SAMPLES_MS \
        PERF_HTTPS_WIREGUARD_UDP_FRESH_SAMPLES_MS PERF_HTTPS_WIREGUARD_UDP_REUSED_SAMPLES_MS; do
        grep -q "^ANDROID_$metric=" "$working_dir/performance.txt"
    done
    for sample in {1..5}; do
        grep -q "^ANDROID_PERF_VISUAL_DIAGNOSTICS_RECONNECT_$sample=" "$working_dir/performance.txt"
    done
    for route in DIRECT WIREGUARD_UDP; do
        grep -Eq "^ANDROID_PERF_UDP_STUN_${route}_(RTT_MS|STATUS)=.*;HOST=stun[.]cloudflare[.]com;(ENDPOINT=[0-9.]+;)?PORT=3478(;|$)" \
            "$working_dir/performance.txt"
        grep -Eq "^ANDROID_PERF_UDP_STUN_${route}_(RTT_MS|STATUS)=.*;HOST=stun[.]l[.]google[.]com;(ENDPOINT=[0-9.]+;)?PORT=19302(;|$)" \
            "$working_dir/performance.txt"
    done
    # Both idle targets and the Cloudflare target during each load must answer through the VPN.
    # For 12 samples, nearest-rank p95 is the slowest response. Require every sent probe.
    for route in WIREGUARD_UDP WIREGUARD_UDP_DOWNLOAD WIREGUARD_UDP_UPLOAD; do
        expected=1
        [[ "$route" != WIREGUARD_UDP ]] || expected=2
        awk -F ';' -v route="$route" -v expected="$expected" '
          $1 ~ ("^ANDROID_PERF_UDP_STUN_" route "_RTT_MS=") {
            records++; replies=0; exit_ok=0; p95=-1; host=""
            for (i=2; i<=NF; i++) {
              split($i, field, "=")
              if (field[1]=="HOST") host=field[2]
              if (field[1]=="REPLIES") replies=field[2]+0
              if (field[1]=="P95_MS") p95=field[2]+0
              if (field[1]=="VPN_EXIT_VERIFIED") exit_ok=field[2]+0
            }
            if (++hosts[host]==1 && replies==12 && exit_ok==1 && p95>=0 && p95<=500) passed++
          }
          END {exit records!=expected || passed!=expected}' "$working_dir/performance.txt" || {
            echo "Android $route failed the verified 500 ms RTT or probe-delivery target." >&2
            exit 1
        }
    done
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        latency_met=false
        if grep -Eq '^ANDROID_PERF_CONNECT_AFTER_CONSENT_MS=[1-9][0-9]*;TARGET_MS=1000;UNDER_TARGET=1$' \
                "$working_dir/performance.txt" &&
            grep -Eq '^ANDROID_PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS=.*;UNDER_1000MS=5$' \
                "$working_dir/performance.txt"; then
            latency_met=true
        fi
        printf 'latency_met=%s\n' "$latency_met" >> "$GITHUB_OUTPUT"
    fi
    echo 'Production Android TLS, enrollment, WireGuard, DNS, disconnect and test-device removal verified.'
    exit 0
fi

if ! command -v wg >/dev/null; then
    sudo apt-get -q update
    sudo apt-get -qy install wireguard-tools
fi
fixture_file="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/wireguard_fixture.py"
sudo bash -c 'echo "$$" > "$1"; exec python3 -u "$2"' _ "$working_dir/fixture.pid" "$fixture_file" \
    >"$working_dir/fixture.log" 2>&1 &
if ! timeout 25 bash -c 'until curl -fsS -o /dev/null http://127.0.0.1:18081/key 2>/dev/null; do sleep 1; done'; then
    cat "$working_dir/fixture.log"
    exit 1
fi

if [[ -n "${ANDROID_UPGRADE_FROM_APK:-}" ]]; then
    adb install -t "$ANDROID_UPGRADE_FROM_APK"
    adb install -r -t "$app"
    echo 'The owner-signed WireGuard APK installed over the previous Android release.'
else
    adb install -t "$app"
fi
adb install -t "$test_apk"
adb shell am instrument -w org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner \
    | tee "$working_dir/instrumentation.txt"
if ! grep -Eq '^OK \([1-9][0-9]* tests?\)' "$working_dir/instrumentation.txt"; then
    cat "$working_dir/fixture.log"
    sudo wg show wg-proxy-ci latest-handshakes | awk '{ print "Fixture handshake time", $2 }' || true
    sudo wg show wg-proxy-ci transfer | awk '{ print "Fixture bytes received/sent", $2, $3 }' || true
    adb logcat -d -s ProxyTunnel:D AndroidRuntime:E | tail -100 || true
    exit 1
fi
sudo wg show wg-proxy-ci latest-handshakes | awk '$2 > 0 { found = 1 } END { exit !found }'
sudo wg show wg-proxy-ci transfer | awk '$2 > 0 && $3 > 0 { found = 1 } END { exit !found }'
echo 'Android and the Linux peer completed a WireGuard handshake with bidirectional tunnel traffic.'
