#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 || ( $# -eq 4 && "$4" != production ) ]]; then
    echo 'Usage: android-emulator-test.sh API app.apk instrumentation.apk [production]' >&2
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

if [[ "$mode" == production ]]; then
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
    adb shell am instrument -w -e class org.morandi.proxy.ProductionLifecycleTest \
        -e proxyProduction 1 -e proxyUser "$user_b64" -e proxyPass "$pass_b64" \
        -e proxyRun "$GITHUB_RUN_ID" org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner \
        | tee "$working_dir/instrumentation.txt"
    unset user_b64 pass_b64
    download='^ANDROID_DOWNLOAD_(DIRECT|WIREGUARD_UDP)_BYTES=[0-9]+;ELAPSED_MS=[0-9]+$'
    timing='^ANDROID_PERF_(LOGIN_(FRESH|SAVED_CONTROLLER|WARM)_MS=[0-9]+;TARGET_MS=1000|'
    timing+='CONNECT_(FIRST_CLICK|AFTER_CONSENT|RECONNECT_CLICK)_MS=[0-9]+;TARGET_MS=1500);UNDER_TARGET=[01]$'
    reconnect_series='^ANDROID_PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS=([0-9]+,){4}[0-9]+'
    reconnect_series+=';N=5;MEDIAN_MS=[0-9]+;MAX_MS=[0-9]+;UNDER_1500MS=[0-5]$'
    login_phases='^ANDROID_PERF_LOGIN_(FRESH|WARM)_PHASES=QUEUE_MS:[0-9]+,IDENTITY_MS:[0-9]+,AUTH_MS:[0-9]+,SESSION_MS:[0-9]+'
    login_phases+=',STREAM_OPEN_MS:[0-9]+,UPLOAD_MS:[0-9]+,RESPONSE_HEADERS_MS:[0-9]+,RESPONSE_BODY_MS:[0-9]+$'
    families='^ANDROID_PERF_VERIFIED_FAMILIES=[12]$'
    proof='^ANDROID_PERF_EXIT_PROOF_(FIRST|RECONNECT)=IPV4:(h3|https);IPV6:(h3|https|blocked);H3_CANDIDATE=[01]$'
    phases='^ANDROID_PERF_CONNECT_PHASES_(FIRST|RECONNECT)=TOTAL_MS:[0-9]+;POLICY_MS:[0-9]+;QUEUE_MS:[0-9]+;PREPARATION_MS:[0-9]+;POLICY_WAIT_MS:[0-9]+;BACKEND_WAIT_MS:[0-9]+;SERVICE_WAIT_MS:[0-9]+;NATIVE_START_MS:[0-9]+;NETWORK_WAIT_MS:[0-9]+'
    phases+=';NETWORK_DISCOVERY_MS:[0-9]+;NETWORK_BIND_MS:[0-9]+;EXIT_PROOF_MS:[0-9]+;WG_HANDSHAKE_MS:(-1|[0-9]+)'
    phases+=';IPV4_PROOF_MS:[0-9]+;IPV4_PROOF_ATTEMPTS:[1-3];IPV6_PROOF_MS:[0-9]+;IPV6_PROOF_ATTEMPTS:[0-3];ATTEMPTS:[0-9]+$'
    latency='^ANDROID_PERF_HTTPS_(DIRECT|WIREGUARD_UDP)_(FRESH|REUSED)_SAMPLES_MS=([0-9]+,){19}[0-9]+'
    latency+=';N=20;MEDIAN_MS=[0-9]+;P95_MS=[0-9]+;UNDER_500MS=[0-9]+;HOST=www[.]cloudflare[.]com'
    latency+=';PATH=/cdn-cgi/trace;ENDPOINT=[0-9.]+;ADDRESS_FAMILY=IPv4;PROTOCOL=HTTP_1_1$'
    rtt_sample='(-1|[0-9]+[.][0-9]{3})'
    rtt="^ANDROID_PERF_UDP_STUN_(DIRECT|WIREGUARD_UDP)_RTT_MS=($rtt_sample,){11}$rtt_sample"
    rtt+=';N=12;REPLIES=[0-9]+;UNANSWERED=[0-9]+;PROBE_LOSS_PERCENT=[0-9]+[.][0-9]{3}'
    rtt+=";MEDIAN_MS=$rtt_sample;P95_MS=$rtt_sample;MEAN_ADJACENT_RTT_CHANGE_MS=$rtt_sample"
    rtt+=';HOST=(stun[.]cloudflare[.]com|stun[.]l[.]google[.]com);ENDPOINT=[0-9.]+;PORT=(3478|19302)'
    rtt+=';TIMEOUT_MS=1200;VPN_EXIT_VERIFIED=[01]$'
    rtt_unavailable='^ANDROID_PERF_UDP_STUN_(DIRECT|WIREGUARD_UDP)_STATUS=(DNS_UNAVAILABLE|NO_IPV4_ADDRESS)'
    rtt_unavailable+=';HOST=(stun[.]cloudflare[.]com|stun[.]l[.]google[.]com);PORT=(3478|19302)$'
    adb logcat -d -v raw -s ProxySpeedAcceptance:I '*:S' |
        grep -E -e "$download" -e "$timing" -e "$reconnect_series" -e "$login_phases" -e "$families" -e "$proof" \
            -e "$phases" -e "$latency" -e "$rtt" -e "$rtt_unavailable" |
        tee "$working_dir/performance.txt"
    grep -Eq '^OK \(1 test\)' "$working_dir/instrumentation.txt"
    for metric in DOWNLOAD_DIRECT_BYTES DOWNLOAD_WIREGUARD_UDP_BYTES PERF_VERIFIED_FAMILIES \
        PERF_LOGIN_FRESH_MS PERF_LOGIN_SAVED_CONTROLLER_MS PERF_LOGIN_WARM_MS \
        PERF_LOGIN_FRESH_PHASES PERF_LOGIN_WARM_PHASES \
        PERF_CONNECT_FIRST_CLICK_MS PERF_CONNECT_AFTER_CONSENT_MS PERF_CONNECT_RECONNECT_CLICK_MS \
        PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS \
        PERF_EXIT_PROOF_FIRST PERF_EXIT_PROOF_RECONNECT \
        PERF_CONNECT_PHASES_FIRST PERF_CONNECT_PHASES_RECONNECT \
        PERF_HTTPS_DIRECT_FRESH_SAMPLES_MS PERF_HTTPS_DIRECT_REUSED_SAMPLES_MS \
        PERF_HTTPS_WIREGUARD_UDP_FRESH_SAMPLES_MS PERF_HTTPS_WIREGUARD_UDP_REUSED_SAMPLES_MS; do
        grep -q "^ANDROID_$metric=" "$working_dir/performance.txt"
    done
    for route in DIRECT WIREGUARD_UDP; do
        grep -Eq "^ANDROID_PERF_UDP_STUN_${route}_(RTT_MS|STATUS)=.*;HOST=stun[.]cloudflare[.]com;(ENDPOINT=[0-9.]+;)?PORT=3478(;|$)" \
            "$working_dir/performance.txt"
        grep -Eq "^ANDROID_PERF_UDP_STUN_${route}_(RTT_MS|STATUS)=.*;HOST=stun[.]l[.]google[.]com;(ENDPOINT=[0-9.]+;)?PORT=19302(;|$)" \
            "$working_dir/performance.txt"
    done
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        latency_met=false
        if grep -Eq '^ANDROID_PERF_CONNECT_AFTER_CONSENT_MS=[1-9][0-9]*;TARGET_MS=1500;UNDER_TARGET=1$' \
                "$working_dir/performance.txt" &&
            grep -Eq '^ANDROID_PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS=.*;UNDER_1500MS=5$' \
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
