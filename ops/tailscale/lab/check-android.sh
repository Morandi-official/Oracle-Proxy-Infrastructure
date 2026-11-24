#!/usr/bin/env bash
set -euo pipefail

apk=${1:?fixture APK required}
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
package=org.morandi.proxy.tailscale.fixture
image='system-images;android-36;google_apis;x86_64'
avd=proxy-tailnet-runtime
scratch=$(mktemp -d)
trap 'adb emu kill >/dev/null 2>&1 || true; rm -rf -- "$scratch"' EXIT

test -e /dev/kvm
sudo chmod a+rw /dev/kvm
sdkmanager platform-tools emulator "$image"
printf 'no\n' | avdmanager create avd --force --name "$avd" --package "$image" --device pixel
"$ANDROID_HOME/emulator/emulator" -avd "$avd" -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect > "$scratch/emulator.log" 2>&1 &
timeout 180 adb wait-for-device
timeout 180 bash -c 'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'
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
