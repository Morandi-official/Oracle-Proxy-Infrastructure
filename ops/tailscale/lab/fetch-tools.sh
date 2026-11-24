#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly destination=${1:?output directory required}
readonly headscale_version=0.29.7
readonly tailscale_version=1.104.7
readonly headscale_digest=e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8

test "$(uname -m)" = x86_64
mkdir -- "$destination"
destination_dir=$(realpath "$destination")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

curl --fail --silent --show-error --location --proto '=https' --max-time 90 \
    "https://github.com/juanfont/headscale/releases/download/v$headscale_version/headscale_${headscale_version}_linux_amd64" \
    --output "$destination_dir/headscale"
printf '%s  %s\n' "$headscale_digest" "$destination_dir/headscale" | sha256sum --check --status
chmod 0700 "$destination_dir/headscale"

# APT verifies the vendor-signed index and the exact package checksum.
curl --fail --silent --show-error --proto '=https' --max-time 45 \
    https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg --output "$scratch/tailscale.gpg"
printf 'deb [signed-by=%s] https://pkgs.tailscale.com/stable/ubuntu noble main\n' \
    "$scratch/tailscale.gpg" > "$scratch/sources.list"
mkdir "$scratch/lists" "$scratch/archives"
apt_options=(
    -o "Dir::Etc::sourcelist=$scratch/sources.list"
    -o 'Dir::Etc::sourceparts=-'
    -o "Dir::State::lists=$scratch/lists"
    -o "Dir::Cache::archives=$scratch/archives"
)
cd "$scratch"
apt-get "${apt_options[@]}" update -qq
apt-get "${apt_options[@]}" download "tailscale=$tailscale_version"
dpkg-deb --extract tailscale_*_amd64.deb package
install -m 0700 -- package/usr/bin/tailscale package/usr/sbin/tailscaled "$destination_dir/"
"$destination_dir/headscale" version
"$destination_dir/tailscale" version
