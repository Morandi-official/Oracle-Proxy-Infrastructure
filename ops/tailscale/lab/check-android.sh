#!/usr/bin/env bash
set -euo pipefail

apk=${1:?fixture APK required}
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
package=org.morandi.proxy.tailscale.fixture
image='system-images;android-36;google_apis;x86_64'
avd=proxy-tailnet-runtime
scratch=$(mktemp -d)
export ANDROID_USER_HOME="$scratch/android-user"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
emulator_pid=

cleanup() {
    adb emu kill >/dev/null 2>&1 || true
    if [[ -n "$emulator_pid" ]]; then
        kill "$emulator_pid" 2>/dev/null || true
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT

test -e /dev/kvm
sudo chmod a+rw /dev/kvm
sdkmanager platform-tools emulator "$image"
printf 'no\n' | avdmanager create avd --force --name "$avd" --package "$image" \
    --path "$ANDROID_AVD_HOME/$avd.avd"
"$ANDROID_HOME/emulator/emulator" -list-avds | grep -Fxq "$avd"
"$ANDROID_HOME/emulator/emulator" -avd "$avd" -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect -accel on > "$scratch/emulator.log" 2>&1 &
emulator_pid=$!
sleep 2
if ! kill -0 "$emulator_pid" 2>/dev/null || ! timeout 180 adb wait-for-device; then
    cat "$scratch/emulator.log" >&2
    exit 1
fi
if ! timeout 180 bash -c 'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'; then
    cat "$scratch/emulator.log" >&2
    exit 1
fi
adb shell input keyevent 82
adb install "$apk"
adb shell appops set "$package" ACTIVATE_VPN allow
adb logcat -c
adb shell am start -n "$package/org.morandi.proxy.tailscale.RuntimeFixture"
for _ in {1..40}; do
    log=$(adb logcat -d -s ProxyTailLab)
    if [[ "$log" == *TAILSCALE_ANDROID_RUNTIME_LOCAL_CONTROL=PASS* ]]; then
        echo 'TAILSCALE_ANDROID_RUNTIME_LOCAL_CONTROL=PASS'
        adb shell am force-stop "$package"
        exit 0
    fi
    if [[ "$log" == *MISSING* || "$log" == *FAILED* ]]; then
        printf '%s\n' "$log" >&2
        exit 1
    fi
    sleep 1
done
echo 'TAILSCALE_ANDROID_RUNTIME_CONTROL_NOT_OBSERVED' >&2
adb logcat -d -s ProxyTailLab AndroidRuntime >&2
exit 1
