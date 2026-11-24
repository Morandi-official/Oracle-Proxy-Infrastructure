#!/usr/bin/env bash
set -euo pipefail

for name in ANDROID_SIGNING_KEYSTORE_B64 ANDROID_SIGNING_KEYSTORE_PASSWORD ANDROID_SIGNING_KEY_ALIAS ANDROID_SIGNING_KEY_PASSWORD; do
    if [[ -z "${!name:-}" ]]; then
        echo "Missing Android signing configuration: $name" >&2
        exit 1
    fi
done

umask 077
export ANDROID_SIGNING_STORE_PATH
ANDROID_SIGNING_STORE_PATH=$(mktemp "$RUNNER_TEMP/proxy-signing.XXXXXXXX")
trap 'rm -f -- "$ANDROID_SIGNING_STORE_PATH"' EXIT
printf '%s' "$ANDROID_SIGNING_KEYSTORE_B64" | base64 --decode > "$ANDROID_SIGNING_STORE_PATH"
unset ANDROID_SIGNING_KEYSTORE_B64

app=clients/android/tailscale-app
bridge="$GITHUB_WORKSPACE/upstream/tailscale-android/android/libs/libtailscale_unstripped.aar"
gradle --no-daemon -p "$app" -PtailscaleBridge="$bridge" \
    -PproxyNoticeDirectory="$RUNNER_TEMP/proxy-notices" -PproxyTestRelease=true \
    assembleRelease assembleReleaseAndroidTest

shopt -s nullglob
products=("$app"/build/outputs/apk/release/*-release.apk)
tests=("$app"/build/outputs/apk/androidTest/release/*-release-androidTest.apk)
test "${#products[@]}" -eq 1
test "${#tests[@]}" -eq 1
tools="$ANDROID_HOME/build-tools/36.0.0"
signer() {
    "$tools/apksigner" verify --min-sdk-version 29 --print-certs "$1" |
        sed -n 's/^Signer #1 certificate SHA-256 digest: //p'
}
app_signer=$(signer "${products[0]}")
test_signer=$(signer "${tests[0]}")
[[ "$app_signer" =~ ^[0-9a-f]{64}$ && "$app_signer" == "$test_signer" ]]
archive_entries=$(unzip -Z1 "${products[0]}")
grep -Fxq 'lib/arm64-v8a/libgojni.so' <<< "$archive_entries"
grep -Fxq 'lib/x86_64/libgojni.so' <<< "$archive_entries"
grep -Fxq 'assets/licenses/tailscale-android.txt' <<< "$archive_entries"
grep -Fxq 'assets/licenses/tailscale.txt' <<< "$archive_entries"
package=$("$tools/aapt" dump badging "${products[0]}" | sed -n '1p')
[[ "$package" == "package: name='org.morandi.proxy' versionCode='"* ]]
version=$(sed -n "s/.*versionName='\([0-9.]*\)'.*/\1/p" <<< "$package")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

output="$RUNNER_TEMP/tailscale-android-signed"
mkdir -- "$output"
cp -- "${products[0]}" "$output/Proxy-Android.apk"
(cd "$output" && sha256sum Proxy-Android.apk > SHA256SUMS.txt)
printf 'artifact=tailscale-android-signed\nversion=%s\n' "$version" >> "$GITHUB_OUTPUT"
