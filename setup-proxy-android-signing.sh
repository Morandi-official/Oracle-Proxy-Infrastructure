#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

repo=Morandi-official/Oracle-Proxy-Infrastructure
environment=android-release
workflow=android-client.yml
release_tag=android-v0.1.0
key_alias=proxy-android
state_dir="$HOME/.proxy-android-signing"
signer="$state_dir/signer"
keystore="$signer/proxy-android-release.p12"
password_file="$signer/password"
env_api="repos/$repo/environments/$environment"
signing_secrets=(ANDROID_SIGNING_KEYSTORE_B64 ANDROID_SIGNING_KEYSTORE_PASSWORD ANDROID_SIGNING_KEY_ALIAS ANDROID_SIGNING_KEY_PASSWORD)

stop() { printf '%s\n' "$*" >&2; exit 1; }

[[ $# == 0 ]] || stop 'Run this script without arguments.'
[[ ! -L "$state_dir" ]] || stop 'The signing directory is a symbolic link. Review it before continuing.'
mkdir -p -- "$state_dir"
chmod 700 -- "$state_dir"
if command -v flock >/dev/null; then
    exec 9>"$state_dir/setup.lock"
    flock -n 9 || stop 'Another Android signing setup is running in this Cloud Shell.'
fi
scratch="$(mktemp -d "$state_dir/setup.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

if ! command -v gh >/dev/null; then
    case "$(uname -m)" in
        x86_64) arch=amd64; digest=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f ;;
        aarch64|arm64) arch=arm64; digest=b1278c75107423d818f1937fd92cafc9e5e9b606631568f68d7fb816f5885a02 ;;
        *) stop 'Install the GitHub CLI for this Cloud Shell architecture.' ;;
    esac
    package="gh_2.105.0_linux_$arch"
    curl -fsSL --proto '=https' --connect-timeout 12 --max-time 90 \
        "https://github.com/cli/cli/releases/download/v2.105.0/$package.tar.gz" -o "$scratch/gh.tar.gz"
    printf '%s  %s\n' "$digest" "$scratch/gh.tar.gz" | sha256sum -c --status
    tar -xzf "$scratch/gh.tar.gz" -C "$scratch" "$package/bin/gh"
    export PATH="$scratch/$package/bin:$PATH"
fi

if ! gh auth status --hostname github.com >/dev/null 2>&1; then
    # A preconfigured CLI login can still be valid if an ambient token is stale.
    unset GH_TOKEN GITHUB_TOKEN
    if ! gh auth status --hostname github.com >/dev/null 2>&1; then
        printf '%s\n' '在 GitHub 官方页面完成一次设备授权。请直接使用终端显示的网址和设备码。'
        gh auth login --hostname github.com --git-protocol https --web
    fi
fi

[[ "$(gh api "repos/$repo" --jq '.permissions.admin')" == true ]] \
    || stop "This GitHub login needs admin access to $repo to configure its release environment."

if gh release view "$release_tag" --repo "$repo" --json assets --jq '.assets[].name' 2>/dev/null \
    | grep -Fxq 'Proxy-Android.apk'; then
    printf '该版本已发布\nhttps://github.com/%s/releases/download/%s/Proxy-Android.apk\n' "$repo" "$release_tag"
    exit 0
fi

# The Android signing key is scoped to main. Preserve the approval and branch
# rules of any existing environment.
if ! gh api "$env_api" >"$scratch/environment.json" 2>"$scratch/environment-error"; then
    grep -q 'HTTP 404' "$scratch/environment-error" || { cat "$scratch/environment-error" >&2; exit 1; }
    gh api --method PUT "$env_api" --input - >/dev/null <<'JSON'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
fi

policy="$(gh api "$env_api" --jq '.deployment_branch_policy | (.custom_branch_policies == true) and (.protected_branches == false)')"
if [[ "$policy" != true ]]; then
    unconfigured="$(gh api "$env_api" --jq '(.deployment_branch_policy == null) and ((.protection_rules // []) | length == 0)')"
    if [[ "$unconfigured" == true ]] && [[ -z "$(gh secret list --repo "$repo" --env "$environment" --json name --jq '.[].name')" ]]; then
        gh api --method PUT "$env_api" --input - >/dev/null <<'JSON'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
        policy="$(gh api "$env_api" --jq '.deployment_branch_policy | (.custom_branch_policies == true) and (.protected_branches == false)')"
    fi
fi
[[ "$policy" == true ]] || stop 'The existing android-release environment must use a selected-branches policy with only main.'
branches() {
    gh api --paginate "$env_api/deployment-branch-policies" --jq '.branch_policies[] | "\(.type // "branch"):\(.name)"'
}
rules="$(branches)"
if [[ -z "$rules" ]]; then
    gh api --method POST "$env_api/deployment-branch-policies" -f name=main -f type=branch >/dev/null
    rules="$(branches)"
fi
[[ "$rules" == branch:main ]] || stop 'The existing android-release environment has other allowed branches or tags. Review its policy before uploading the key.'

remote="$(gh secret list --repo "$repo" --env "$environment" --json name --jq '.[].name')"
present=0
for name in "${signing_secrets[@]}"; do
    if grep -Fxq "$name" <<<"$remote"; then
        present=$((present + 1))
    fi
done

if [[ "$present" -lt 4 ]]; then
    [[ ! -L "$signer" && ! -L "$keystore" && ! -L "$password_file" ]] || stop 'A signing file is a symbolic link.'
    if [[ ! -e "$signer" ]]; then
        [[ "$present" == 0 ]] || stop 'Some signing secrets already exist, but this Cloud Shell has no matching signing key. Existing secrets were preserved.'
        command -v keytool >/dev/null || stop 'keytool was not found. Select the Cloud Shell JDK and run the script again.'
        mkdir -m 700 -- "$scratch/signer"
        openssl rand -hex 32 >"$scratch/signer/password"
        keytool -genkeypair -storetype PKCS12 \
            -keystore "$scratch/signer/proxy-android-release.p12" -alias "$key_alias" \
            -storepass:file "$scratch/signer/password" -keypass:file "$scratch/signer/password" \
            -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 10000 \
            -dname 'CN=Morandi Proxy' -noprompt >/dev/null 2>&1 \
            || stop 'Cloud Shell could not generate the Android signing key.'
        printf '%s\n' "$repo/$environment/$key_alias" >"$scratch/signer/created-for"
        mv -T -- "$scratch/signer" "$signer"
    fi

    [[ -f "$keystore" && -f "$password_file" && -f "$signer/created-for" ]] \
        && [[ "$(cat "$signer/created-for")" == "$repo/$environment/$key_alias" ]] \
        || stop 'The saved signer is incomplete or belongs to another environment.'
    command -v keytool >/dev/null || stop 'keytool is required to verify the saved signer.'
    keytool -list -storetype PKCS12 -keystore "$keystore" -alias "$key_alias" \
        -storepass:file "$password_file" >/dev/null 2>&1 || stop 'The saved signing key could not be verified.'

    for name in "${signing_secrets[@]}"; do
        if grep -Fxq "$name" <<<"$remote"; then
            continue
        fi
        case "$name" in
            ANDROID_SIGNING_KEYSTORE_B64) base64 <"$keystore" | tr -d '\r\n' ;;
            ANDROID_SIGNING_KEY_ALIAS) printf '%s' "$key_alias" ;;
            *) tr -d '\r\n' <"$password_file" ;;
        esac | gh secret set "$name" --repo "$repo" --env "$environment"
    done
    remote="$(gh secret list --repo "$repo" --env "$environment" --json name --jq '.[].name')"
fi

for name in "${signing_secrets[@]}"; do
    grep -Fxq "$name" <<<"$remote" || stop "GitHub did not confirm $name."
done
printf '%s\n' 'GitHub 已确认 4 项 Android 签名 Secrets。'
if [[ -f "$keystore" ]]; then
    printf '签名库与口令文件保存在当前 OCI 用户的私有目录 %s\n' "$signer"
fi

active="$(gh run list --repo "$repo" --workflow "$workflow" --branch main \
    --event workflow_dispatch --limit 10 --json status,url --jq '[.[] | select(.status != "completed")][0].url // empty')"
if [[ -n "$active" ]]; then
    printf '已有发布工作流正在运行\n%s\n' "$active"
    exit 0
fi

run_url="$(gh api --method POST -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repo/actions/workflows/$workflow/dispatches" --input - --jq '.html_url // empty' <<'JSON'
{"ref":"main","inputs":{"publish":"true"}}
JSON
)"
printf '%s\n' '已触发发布验收。工作流需要验证签名 APK 和生产连接，然后才会发布。'
if [[ -n "$run_url" ]]; then
    printf '%s\n' "$run_url"
else
    printf 'https://github.com/%s/actions/workflows/%s\n' "$repo" "$workflow"
fi
