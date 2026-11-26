#!/usr/bin/env bash
# Promote the already signed Android 0.2.0 candidate. No build or signing credentials.
set -euo pipefail
trap 'echo "Android release verification failed at script line $LINENO" >&2' ERR
export LC_ALL=C
export GH_REPO=Morandi-official/Oracle-Proxy-Infrastructure
[[ ${GITHUB_REPOSITORY:?} == "$GH_REPO" ]]
mode=${1:?expected verify or publish}
[[ $mode == verify || ( $mode == publish && ${GITHUB_REF:?} == refs/heads/main ) ]]

source_sha=94875ec083b90daf8d5d2990c1b03cd81416d3c6
run=45823493566
artifact=15119256559
archive_sha=55fa19200984b1c50f265db30183fa1e894ec52a8e25b0b21032e2e4b6dc9f5d
certificate=7013216d7befbbe128b5c218e96daa05c16829c2bf45f6db9b9ac09628738370
tag=wireguard-android-v0.2.0
apk=Proxy-Android.apk
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
api() { gh api "repos/$GH_REPO/$1"; }

api "actions/runs/$run" | jq -e --arg sha "$source_sha" '
  .head_sha == $sha and .head_branch == "main" and .event == "push" and
  .path == ".github/workflows/android-client.yml" and .run_attempt == 1 and .conclusion == "failure"' >/dev/null
api "actions/runs/$run/attempts/1/jobs?per_page=100" | jq -e '
  .total_count == 8 and
  (.jobs | map({key: .name, value: .conclusion}) | from_entries) == {
    "build":"success", "emulator (29)":"success", "emulator (36)":"success",
    "signed-release":"success", "signed-emulator (29)":"success", "signed-emulator (36)":"success",
    "production-emulator":"failure", "publish":"skipped"} and
  (.jobs[] | select(.name == "production-emulator") |
    .id == 139925274365 and
    [.steps[] | select(.conclusion != "success") | .name] ==
      ["Verify production account and VPN using the signed APK"])' >/dev/null

gh api --allow-escape-sequences "repos/$GH_REPO/actions/jobs/139925274365/logs" > production.log
[[ $(grep -c 'Error in ' production.log) == 1 ]]
grep -Fq 'Error in signedAppAgainstProduction(' production.log
grep -Fq 'Tests run: 1,  Failures: 1' production.log
[[ $(sed -n 's/^.*java.lang.AssertionError: //p' production.log | tr -d '\r' | sort -u) == \
   'Real consent tap to visible verified VPN must complete within 1000 ms' ]]
grep -Fq 'ANDROID_PERF_LOGIN_FOREGROUND_MS=447;' production.log
grep -Fq 'ANDROID_PERF_CONNECT_AFTER_CONSENT_MS=1545;' production.log
grep -Fq 'ANDROID_PERF_CONNECT_PREAUTHORIZED_SAMPLES_MS=1673,1170,1578,1228,1123;' production.log
[[ $(grep -Ec 'ANDROID_PERF_UDP_STUN_WIREGUARD_UDP(_DOWNLOAD|_UPLOAD)?_RTT_MS=.*;N=12;REPLIES=12;UNANSWERED=0;.*;VPN_EXIT_VERIFIED=1' production.log) == 4 ]]

api "actions/artifacts/$artifact" | jq -e --arg digest "sha256:$archive_sha" --arg sha "$source_sha" \
  --argjson run "$run" '.name == "owner-signed-android" and .digest == $digest and
    .expired == false and .workflow_run.id == $run and .workflow_run.head_sha == $sha' >/dev/null
gh api --allow-escape-sequences "repos/$GH_REPO/actions/artifacts/$artifact/zip" > signed.zip
echo "$archive_sha  signed.zip" | sha256sum -c -
[[ $(unzip -Z1 signed.zip | sort) == $'Proxy-Android.apk\nSHA256SUMS.txt\nversion.txt' ]]
for file in "$apk" SHA256SUMS.txt version.txt; do unzip -p signed.zip "$file" > "$file"; done
cmp version.txt <(printf '0.2.0\n')
cmp SHA256SUMS.txt <(sha256sum "$apk")
sha256sum "$apk"

mkdir prior
gh release download wireguard-android-v0.1.0 --pattern "$apk" --dir prior
echo "1c477913fb61ecc2e30cabd0c0dedc2b31fef3cad6ee489ed302231e7b6cd258  prior/$apk" | sha256sum -c -
sdk_tools=$(find "${ANDROID_HOME:?}/build-tools" -mindepth 2 -maxdepth 2 -name apksigner | sort -V | tail -1)
[[ -x $sdk_tools ]]
for signed_apk in "prior/$apk" "$apk"; do
  "$sdk_tools" verify --min-sdk-version 29 --print-certs "$signed_apk" > cert.txt
  [[ $(sed -n 's/^Signer #[0-9]* certificate SHA-256 digest: //p' cert.txt) == "$certificate" ]]
done
"$(dirname "$sdk_tools")/aapt" dump badging "$apk" > badging.txt
grep -Fq "package: name='org.morandi.proxy' versionCode='7' versionName='0.2.0'" badging.txt
grep -Fxq "sdkVersion:'29'" badging.txt
[[ $mode == publish ]] || exit 0

cat > notes.md <<NOTES
WireGuard Android 0.2.0 性能预览版，适用于 Android 10 及以上。安装包沿用 0.1.0 的签名，Android 10 和 Android 16 云端模拟器均通过原位升级与功能测试。

生产出口已验证。云端模拟器前台登录耗时 447 ms，首次点击系统授权至界面显示已验证耗时 1545 ms。五次已授权重连分别耗时 1673、1170、1578、1228、1123 ms，中位数 1228 ms。该安装包仍未达到 1 秒连接目标。

通过代理的 48 次 UDP 探测全部得到响应，四组测量中最高 P95 为 306.864 ms。HTTPS 新连接首字节 P95 为 627 ms，复用连接为 154 ms。

[签名安装包的云端验收记录](https://github.com/$GH_REPO/actions/runs/$run) · 源提交 \`$source_sha\`
NOTES

ref="refs/tags/$tag"
api "git/matching-refs/tags/$tag" | jq -e --arg ref "$ref" --arg sha "$source_sha" \
  '[.[] | select(.ref == $ref)] | all(.object.type == "commit" and .object.sha == $sha)' >/dev/null
gh api --paginate "repos/$GH_REPO/releases?per_page=100" |
  jq -sc --arg tag "$tag" '[.[][] | select(.tag_name == $tag)]' > matches.json
count=$(jq length matches.json)
if [[ $count == 0 ]]; then
  jq -n --arg tag "$tag" --arg sha "$source_sha" --rawfile notes notes.md '{
    tag_name:$tag, target_commitish:$sha, name:"Proxy WireGuard Android 0.2.0 性能预览版",
    body:$notes, draft:true, prerelease:true, make_latest:"false"}' |
    gh api -X POST "repos/$GH_REPO/releases" --input - > release.json
else
  [[ $count == 1 ]]
  jq '.[0]' matches.json > release.json
fi
jq -e --arg sha "$source_sha" --rawfile notes notes.md '
  .target_commitish == $sha and .prerelease and
  ((.body | rtrimstr("\n")) == ($notes | rtrimstr("\n")))' release.json >/dev/null
release_id=$(jq -er .id release.json)
draft=$(jq -r .draft release.json)
api "releases/$release_id/assets" > assets.json
jq -e 'all(.name == "Proxy-Android.apk" or .name == "SHA256SUMS.txt")' assets.json >/dev/null
for file in "$apk" SHA256SUMS.txt; do
  if ! jq -e --arg name "$file" 'any(.name == $name)' assets.json >/dev/null; then
    [[ $draft == true ]]
    gh release upload "$tag" "$file"
  fi
done
api "releases/$release_id/assets" > assets.json
for file in "$apk" SHA256SUMS.txt; do
  digest=$(sha256sum "$file" | cut -d' ' -f1)
  jq -e --arg file "$file" --arg digest "sha256:$digest" \
    'length == 2 and any(.name == $file and .state == "uploaded" and .digest == $digest)' assets.json >/dev/null
done
if [[ $draft == true ]]; then
  gh api -X PATCH "repos/$GH_REPO/releases/$release_id" -F draft=false -f make_latest=false >/dev/null
fi
api "releases/$release_id" | jq -er --arg tag "$tag" --arg sha "$source_sha" '
  select(.tag_name == $tag and .target_commitish == $sha and .draft == false and .prerelease) | .html_url'
for file in "$apk" SHA256SUMS.txt; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 4 --retry-all-errors --connect-timeout 8 --max-time 60 \
    "https://github.com/$GH_REPO/releases/download/$tag/$file" --output "public-$file"
  cmp "$file" "public-$file"
done
echo 'Both public release downloads match the tested files.'
