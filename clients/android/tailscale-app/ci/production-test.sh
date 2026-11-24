#!/usr/bin/env bash
set -euo pipefail

test "$#" -eq 3
application=$(realpath "$1")
instrumentation=$(realpath "$2")
metrics_file=$(realpath -m "$3")
: "${ANDROID_ACCEPTANCE_USERNAME:?Dedicated Oracle acceptance user required}"
: "${ANDROID_ACCEPTANCE_PASSWORD:?Dedicated Oracle acceptance password required}"

umask 077
scratch=$(mktemp -d)
export ANDROID_USER_HOME="$scratch/android-user"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
mkdir -p -- "$ANDROID_AVD_HOME"
emulator_pid=
cleanup() {
    adb emu kill >/dev/null 2>&1 || true
    if [[ -n "$emulator_pid" ]]; then kill "$emulator_pid" 2>/dev/null || true; fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT

test -e /dev/kvm
sudo chmod a+rw /dev/kvm
image='system-images;android-36;google_apis;x86_64'
sdkmanager platform-tools emulator "$image"
printf 'no\n' | avdmanager create avd --force --name proxy-tailscale-release --package "$image" \
    --path "$ANDROID_AVD_HOME/proxy-tailscale-release.avd"
"$ANDROID_HOME/emulator/emulator" -avd proxy-tailscale-release -no-window -no-audio \
    -no-boot-anim -no-snapshot -gpu swiftshader_indirect -accel on > "$scratch/emulator.log" 2>&1 &
emulator_pid=$!
if ! timeout 180 adb wait-for-device || ! timeout 180 bash -c \
    'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'; then
    cat "$scratch/emulator.log" >&2
    exit 1
fi

adb shell input keyevent 82
adb install -t "$application"
adb install -t "$instrumentation"
user_b64=$(printf '%s' "$ANDROID_ACCEPTANCE_USERNAME" | base64 -w0)
password_b64=$(printf '%s' "$ANDROID_ACCEPTANCE_PASSWORD" | base64 -w0)
printf '::add-mask::%s\n' "$user_b64" "$password_b64"
unset ANDROID_ACCEPTANCE_USERNAME ANDROID_ACCEPTANCE_PASSWORD

adb shell am instrument -w -e class org.morandi.proxy.tailscale.ProductionAcceptanceTest \
    -e proxyProduction 1 -e proxyUser "$user_b64" -e proxyPass "$password_b64" \
    org.morandi.proxy.test/androidx.test.runner.AndroidJUnitRunner | tee "$scratch/acceptance.txt"
unset user_b64 password_b64
grep -Eq '^OK \(1 test\)' "$scratch/acceptance.txt"
python3 - "$scratch/acceptance.txt" "$metrics_file" <<'PY'
import json
from pathlib import Path
import sys

log, destination = map(Path, sys.argv[1:])
prefix = "INSTRUMENTATION_STATUS: proxyMetrics="
reports = [json.loads(line.split(prefix, 1)[1]) for line in log.read_text().splitlines() if prefix in line]
if len(reports) != 1:
    raise SystemExit("Expected one Oracle Android acceptance report")
destination.write_text(json.dumps(reports[0], indent=2, sort_keys=True, allow_nan=False) + "\n")
PY
