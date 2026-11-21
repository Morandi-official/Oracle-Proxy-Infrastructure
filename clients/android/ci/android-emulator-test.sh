#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo 'Usage: android-emulator-test.sh API app.apk instrumentation.apk' >&2
    exit 2
fi
api="$1"
app="$2"
test_apk="$3"
image="system-images;android-${api};google_apis;x86_64"
avd="proxy-api-${api}"
working_dir="$(mktemp -d)"
emulator_pid=
cleanup() {
    adb emu kill >/dev/null 2>&1 || true
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
    fi
    sudo ip link del wg-proxy-ci 2>/dev/null || true
    if [[ -f "$working_dir/fixture.pid" ]]; then
        sudo kill "$(cat "$working_dir/fixture.pid")" 2>/dev/null || true
    fi
    rm -rf -- "$working_dir"
}
trap cleanup EXIT

[[ -e /dev/kvm ]] || { echo 'Android acceptance requires KVM on the runner.' >&2; exit 1; }
sudo chmod a+rw /dev/kvm
sdkmanager platform-tools emulator "$image"
printf 'no\n' | avdmanager create avd --force --name "$avd" --package "$image"
emulator -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect -accel on \
    >"$working_dir/emulator.log" 2>&1 &
emulator_pid=$!
if ! timeout 180 adb wait-for-device; then
    cat "$working_dir/emulator.log"
    exit 1
fi
if ! timeout 180 bash -c 'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'; then
    cat "$working_dir/emulator.log"
    exit 1
fi
adb shell input keyevent 82
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0

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

adb install "$app"
adb install "$test_apk"
adb shell am instrument -w org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner \
    | tee "$working_dir/instrumentation.txt"
grep -Eq '^OK \([1-9][0-9]* tests?\)' "$working_dir/instrumentation.txt"
sudo wg show wg-proxy-ci latest-handshakes | awk '$2 > 0 { found = 1 } END { exit !found }'
sudo wg show wg-proxy-ci transfer | awk '$2 > 0 && $3 > 0 { found = 1 } END { exit !found }'
echo 'Android and the Linux peer completed a WireGuard handshake with bidirectional tunnel traffic.'
